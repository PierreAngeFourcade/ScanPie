#!/usr/bin/env python
# -*- coding: Utf-8 -*-

from sys import exit, argv
import errno
from time import time, strftime
from optparse import OptionParser
from collections import OrderedDict
import re
from bs4 import BeautifulSoup

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from ipaddress import ip_address, ip_network, IPv4Address, IPv6Address, IPv4Network, IPv6Network
from urllib2 import urlopen, URLError
import socket
import struct
from fcntl import ioctl

from threading import Thread, Lock
from Queue import Queue

from scapy.all import *

VERBOSE = 0
GLOBAL_LOCK = Lock()

def ifaceAddress(ifname):
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	try:
		return socket.inet_ntoa(ioctl(
		sock.fileno(),
		0x8915,  # SIOCGIFADDR
		struct.pack('256s', ifname[:15]) )[20:24])
	except IOError:
		raise IOError(ifname + ' has no IP address')

def isPrivate(ipSpec):
	if ipSpec.find('/') == -1:
		try: return ip_address(unicode(ipSpec)).is_private
		except: return False
	else:
		try: return ip_network(unicode(ipSpec)).is_private
		except: return False
		
def int32ToInts8(d):
	return [(d>>i*8)&0xFF for i in reversed(range(4))]

def ints8ToInt32(d):
	return sum(d[i]<<(3-i)*8 for i in range(4))

def ipStrToInt(ipStr):
	return ints8ToInt32(map(int, ipStr.split('.')))

def ipIntToStr(ipInt):
	return '.'.join(map(str, int32ToInts8(ipInt)))

def prefixToMask(prefix):
	return int(('1'*prefix) + '0'*(32-prefix), 2)

def networkToHosts(ipWithPrefix):
	ip, prefix = ipWithPrefix.split('/')
	prefix = int(prefix)
	#print 'prefix:', prefix
	ipFields = list(map(int, ip.split('.')))
	ipInt = ints8ToInt32(ipFields)
	#print 'IP:', bin(ipInt), ipInt, ipFields
	mask = prefixToMask(prefix)
	#print 'Mask:', bin(mask), mask, int32ToInts8(mask)
	curIp = mask & ipInt
	#print 'Network address:', bin(curIp), curIp, int32ToInts8(curIp)
	invMask = 2**(32-prefix)-1

	while curIp & invMask < invMask-1:
		curIp += 1
		#if not (curIp % invMask) % (invMask/32+1):
		#	print 'Current IP:', bin(curIp), curIp, int32ToInts8(curIp)
		yield '.'.join(map(str, int32ToInts8(curIp)))

def ipv4Range(ipStringRange):
	fieldRanges = []
	for field in ipStringRange.split('.'):
		count = field.count('-')
		if count > 1:
			raise ValueError('Wrong syntax for ip range')
		elif count == 1:
			start, end = map(int, field.split('-'))
			fieldRanges.append((start, end+1))
		else:
			fieldRanges.append((int(field), int(field)+1))

	for i0 in range(*fieldRanges[0]):
		for i1 in range(*fieldRanges[1]):
			for i2 in range(*fieldRanges[2]):
				for i3 in range(*fieldRanges[3]):
					yield '{}.{}.{}.{}'.format(i0, i1, i2, i3)

def handleIps(ipSpecs, handlePrefix=True, handleRange=True):
	ips = []
	for ipSpec in ipSpecs: # TODO: tests
		if ipSpec.find('/') != -1:
			try:
				net, prefix = ipSpec.split('/')
				ipSpec = socket.gethostbyname(net) + '/' + prefix
				ip_network(unicode(ipSpec)) # Validation
			except ValueError: 
				if VERBOSE: print 'Error: malformed network ip'
				continue
			if handlePrefix: ips.extend(networkToHosts(ipSpec))
			else: ips.append(ipSpec)
		elif ipSpec.find('-') != -1 and handleRange:
			# TODO: validation
			ips.extend(ipv4Range(ipSpec))
		else:
			try:
				ipSpec = socket.gethostbyname(ipSpec)
				ip_address(unicode(ipSpec)) # Validation
			except:
				if VERBOSE: print 'Error: malformed ip'
				continue
			ips.append(ipSpec)
			
	ownAddr = ifaceAddress(conf.iface)
	if ownAddr in ips:
		ips.remove(ownAddr)
	return ips

def port_range(portStringRange):
	if portStringRange.count('-') != 1:
		raise ValueError('Wrong syntax for port range')
	start, end = map(int, portStringRange.split('-'))
	return [port for port in range(start, end+1)]

def handlePorts(portStrings):
	ports = []
	for portString in portStrings:
		if portString == "common":
			ports.extend(COMMON_PORTS)
		elif portString == "very_common":
			ports.extend(VERY_COMMON_PORTS)
		elif portString == "database":
			ports.extend(DATABASE_PORTS)
		elif portString == "email":
			ports.extend(EMAIL_PORTS)
		elif portString == "shared_service":
			ports.extend(SHARED_SERVICE_PORTS)
		elif portString == "auth":
			ports.extend(AUTH_PORTS)
		elif portString == "other":
			ports.extend(OTHER_PORTS)
		elif portString == "voip":
			ports.extend(VOIP_PORTS)
		elif portString.find('-') != -1:
			ports.extend(port_range(portString))
		else:
			try:
				ports.append(int(portString))
			except ValueError:
				print 'Error: Invalid port, port category or port range.'
				exit(-1)
	return ports
	

def tcp_connect(ips, ports, results):
	print "\nRéalisation d'un scan TCP connect\n"
	
	def scan(structure):
		results, dstIp, dstPort = structure
		etat, service, os = '', '', ''

		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.settimeout(2)
		try:
			sock.connect((dstIp, dstPort))
			service = servFingerprinting2(dstIp, dstPort, sock)
			sock.close()
			etat = 'open'
		except socket.timeout:
			etat = 'filtered'
		except socket.error:
			etat = 'closed'

		results[dstIp].append((dstPort, etat, service))
		if VERBOSE: print 'ip ' + dstIp + ' port ' + str(dstPort) + ' ' + etat

	upper, lower = max(len(ips), len(ports)), min(len(ports), len(ips))
	print("pool base:", min(upper * min(4, lower), 1024))
	pool = ThreadPool(min(upper * min(4, lower), 1024))
	pool.map(scan, [(results, ip, port) for port in ports for ip in ips])
	pool.close()
	pool.join()
	return results


def parallelScan(scan, ips, ports, results):
	
	def asyncScan(queue, results, ports):
		while True:
			ip = queue.get()
			try:
				results[ip] = scan(ip, ports)
			except IOError as e:
				print(e); raise
			finally:
				queue.task_done()

	poolSize = min(len(ips), 512)
	print "Pool size:", poolSize
	queue = Queue()
	
	for i in range(poolSize):
		worker = Thread(target=asyncScan, args=(queue, results, ports))
		worker.daemon = True
		worker.start()
	
	for ip in ips:
		queue.put(ip)
	queue.join()
	
	return results

def syn(ip, ports):
	result = ['']
	ans, _ = sr(IP(dst=ip)/TCP(sport=80,dport=ports,flags="S"), inter=.1, timeout=2, verbose=(VERBOSE==2))
		
	for req, res in ans:
		etat, service, cve = '', '', ''
		if res == None:
			etat = 'nores'
		else:
			reqIp = req.getlayer(IP)
			if(res.haslayer(TCP)):
				resTcp = res.getlayer(TCP)
				if(resTcp.flags == 0x12):
					# Kernel send RST to end connection
					etat = 'open'
					service = servFingerprinting2(reqIp.dst, resTcp.sport)
					if service and not service.startswith('[') \
					and resTcp.sport in [80, 8080, 8008, 8009, 8081, 8888]:
						cve = ' '.join(searchCVE(*service.split('/')))
				elif (resTcp.flags == 0x14):
					etat = 'closed'
				else:
					if VERBOSE: print 'Weird packet:', res.summary()
			elif(res.haslayer(ICMP)):
				if(int(res.getlayer(ICMP).type) == 3 and int(res.getlayer(ICMP).code) in [0,1,2,3,9,10,13]):
					etat = 'filtered'

			if result[0] == '':
				result[0] = passiveOsDetection(res)

		result.append((req.getlayer(TCP).dport, etat, service, cve))
		with GLOBAL_LOCK:
			if VERBOSE: print 'ip', reqIp.dst, 'port', req.getlayer(TCP).dport, etat, cve
		
	return result

def tcp_syn(ips, ports, results):
	print "\nRéalisation d'un scan TCP SYN\n"
	
	srcPort = 80#RandShort()
	try:
		ans, _ = sr(IP(dst=ips)/TCP(sport=srcPort,dport=ports,flags="S"),
			timeout=2, inter=.0001, verbose=VERBOSE)
		
		for req, res in ans:
			etat, service = '', ''
			if res == None:
				etat = 'nores'
			else:
				reqIp = req.getlayer(IP)
				if(res.haslayer(TCP)):
					resTcp = res.getlayer(TCP)
					if(resTcp.flags == 0x12):
						# Kernel send RST to end connection
						etat = 'open'
						service = servFingerprinting2(reqIp.dst, resTcp.sport)
					elif (resTcp.flags == 0x14):
						etat = 'closed'
					else:
						if VERBOSE: print 'Weird packet:', res.summary()
				elif(res.haslayer(ICMP)):
					if(int(res.getlayer(ICMP).type) == 3 and int(res.getlayer(ICMP).code) in [0,1,2,3,9,10,13]):
						etat = 'filtered'

				if results[reqIp.dst][0] == '':
					results[reqIp.dst][0] = passiveOsDetection(res)

			results[reqIp.dst].append((req.getlayer(TCP).dport, etat, service))
			if VERBOSE: print 'ip', reqIp.dst, 'port', req.getlayer(TCP).dport, etat

	except IOError as e:
		print(e)

	return results

def tcp_syn2(ips, ports, results):
	print "\nRéalisation d'un scan TCP SYN\n"
	
	def scan(queue, lock, results, ports):
		while True:
			ip = queue.get()
			try:
				ans, _ = sr(IP(dst=ip)/TCP(sport=80,dport=ports,flags="S"), timeout=5, inter=.00001, verbose=(VERBOSE==2))
				
				for req, res in ans:
					etat, service = '', ''
					if res == None:
						etat = 'nores'
					else:
						#ip = res.getlayer(IP).src
						port = req.getlayer(TCP).dport
						
						if res.haslayer(TCP):
							resTcp = res.getlayer(TCP)
							if resTcp.flags == 0x12:
								# Kernel send RST to end connection
								etat = 'open'
								service = servFingerprinting2(ip, port)
							elif resTcp.flags == 0x14:
								etat = 'closed'
							else:
								if VERBOSE: print 'Weird packet:', res.summary()
						elif res.haslayer(ICMP):
							if int(res.getlayer(ICMP).type) == 3 and int(res.getlayer(ICMP).code) in [0,1,2,3,9,10,13]:
								etat = 'filtered'

						if results[ip][0] == '':
							results[ip][0] = passiveOsDetection(res)

					with lock:
						results[ip].append((port, etat, service))
						if VERBOSE:
							print 'ip {} port {} {}'.format(ip, port, etat)

			except IOError as e:
				print(e); raise
			finally:
				queue.task_done()

	upper, lower = max(len(ips), len(ports)), min(len(ports), len(ips))
	poolSize = min(len(ips), 512)#min(upper * min(4, lower), 1024)
	print "Pool size:", poolSize
	queue = Queue()
	lock = Lock()
	
	for i in range(poolSize):
		worker = Thread(target=scan, args=(queue, lock, results, ports))
		worker.daemon = True
		worker.start()
	
	for ip in ips:
		queue.put((ip))
	queue.join()
	
	return results

def tcp_syn3(ips, ports, results):
	print "\nRéalisation d'un scan TCP SYN\n"
	
	def scan(queue, lock, results, ports):
		sock = conf.L3socket(filter=None, iface=conf.iface, nofilter=1)
		try:
			while True:
				ip = queue.get()
				try:
					ans, _ = sndrcv(sock, IP(dst=ip)/TCP(sport=80,dport=ports,flags="S"), inter=.00001, timeout=2, verbose=(VERBOSE==2))
					
					for req, res in ans:
						etat, service = '', ''
						if res == None:
							etat = 'nores'
						else:
							#ip = res.getlayer(IP).src
							port = req.getlayer(TCP).dport
							
							if res.haslayer(TCP):
								resTcp = res.getlayer(TCP)
								if resTcp.flags == 0x12:
									# Kernel send RST to end connection
									etat = 'open'
									service = servFingerprinting2(ip, port)
								elif resTcp.flags == 0x14:
									etat = 'closed'
								else:
									if VERBOSE: print 'Weird packet:', res.summary()
							elif res.haslayer(ICMP):
								if int(res.getlayer(ICMP).type) == 3 and int(res.getlayer(ICMP).code) in [0,1,2,3,9,10,13]:
									etat = 'filtered'

							if results[ip][0] == '':
								results[ip][0] = passiveOsDetection(res)

						with lock:
							results[ip].append((port, etat, service))
							if VERBOSE:
								print 'ip {} port {} {}'.format(ip, port, etat)

				except IOError as e:
					print(e); raise
				finally:
					queue.task_done()
		finally:
			sock.close()

	upper, lower = max(len(ips), len(ports)), min(len(ports), len(ips))
	poolSize = min(len(ips), 512)#min(upper * min(4, lower), 1024)
	print "Pool size:", poolSize
	queue = Queue()
	lock = Lock()
	
	for i in range(poolSize):
		worker = Thread(target=scan, args=(queue, lock, results, ports))
		worker.daemon = True
		worker.start()
	
	for ip in ips:
		queue.put((ip))
	queue.join()
	
	return results

def tcp_xmas(ips, port):
	print "Réalisation d'un scan TCP Xmas\n"
	try:
		dstIp = ips
		srcPort = random.randint(1, 65535)#RandShort()
		dstPort = port

		packet = sr1(IP(dst=dstIp)/TCP(dport=dstPort,gflags="FPU"),timeout=5, verbose=VERBOSE)
		if packet == None:
			etat=1
			dumpFile.write(str(dstIp) + " , " + str(dstPort) + " , " + str(etat)+"\n")
		elif(tcp_connect_scan_resp.haslayer(TCP)):
			if(tcp_connect_scan_resp.getlayer(TCP).flags == 0x14):
				etat=0
				dumpFile.write(str(dstIp) + " , " + str(dstPort) + " , " + str(etat)+"\n")
		elif(packet.haslayer(ICMP)):
			if(int(packet.getlayer(ICMP).type)==3 and int(packet.getlayer(ICMP).code) in [1,2,3,9,10,13]):
				etat="F"
				dumpFile.write(str(dstIp) + " , " + str(dstPort) + " , " + str(etat)+"\n")

	except IOError as e:
		print(e)

def tcp_fin(ips, port):
	print "Réalisation d'un scan FIN\n"
	try:
		dstIp = ips
		srcPort = random.randint(1,65535)
		dstPort = port

		packet = sr1(IP(dst=dstIp)/TCP(dport=dstPort,flags="F"),timeout=1, verbose=VERBOSE)
		if packet == None:
			etat=1
			dumpFile.write(str(dstIp) + " , " + str(dstPort) + " , " + str(etat)+"\n")

		elif(packet.haslayer(TCP)):
			if(packet.getlayer(TCP).flags == 0x14):
				petat=0
				dumpFile.write(str(dstIp) + " , " + str(dstPort) + " , " + str(etat)+"\n")

		elif(packet.haslayer(ICMP)):
			if(int(packet.getlayer(ICMP).type)==3 and int(packet.getlayer(ICMP).code) in [1,2,3,9,10,13]):
				etat="F"
				dumpFile.write(str(dstIp) + " , " + str(dstPort) + " , " + str(etat)+"\n")

	except IOError as e:
		print(e)

def tcp_null(ips, port):
	print "Réalisation d'un scan NULL\n"
	try:
		dstIp = ips
		srcPort = random.randint(1,65535)
		dstPort = port

		packet = sr1(IP(dst=dstIp)/TCP(dport=dstPort,flags=""),timeout=1, verbose=VERBOSE)
		if packet == None:
			etat=1
			dumpFile.write(str(dstIp) + " , " + str(dstPort) + " , " + str(etat)+"\n")
		elif(packet.haslayer(TCP)):
			if(packet.getlayer(TCP).flags == 0x14):
				etat=0
				dumpFile.write(str(dstIp) + " , " + str(dstPort) + " , " + str(etat)+"\n")
		elif(packet.haslayer(ICMP)):
			if(int(packet.getlayer(ICMP).type)==3 and int(packet.getlayer(ICMP).code) in [1,2,3,9,10,13]):
				etat="F"
				dumpFile.write(str(dstIp) + " , " + str(dstPort) + " , " + str(etat)+"\n")

	except IOError as e:
		print(e)

def udp(ips, ports, results):
	try:
		srcPort = RandShort()
		for dstPort in ports:
			os, server = '', ''
			for dstIp in ips:
				if VERBOSE: print 'ip', dstIp
				packet1 = sr1(IP(dst=dstIp)/UDP(dport=dstPort),timeout=2, verbose=0)
				if packet1 == None:
					packet2 = sr1(IP(dst=dstIp)/UDP(dport=dstPort),timeout=2, verbose=0)
					if packet2 == None:
						etat = "Open|Filtered"
					elif packet2.haslayer(ICMP):
						if int(packet2.getlayer(ICMP).type) == 3 and int(packet2.getlayer(ICMP).code) == 3:
							etat = "Closed"
						elif(int(packet2.getlayer(ICMP).type) == 3 and int(packet2.getlayer(ICMP).code) in [0,1,2,9,10,13]):
							etat = "Filtered"
				elif packet1.haslayer(ICMP):
					if int(packet1.getlayer(ICMP).type) == 3 and int(packet1.getlayer(ICMP).code) == 3:
						etat = "Closed"
					elif(int(packet1.getlayer(ICMP).type) == 3 and int(packet1.getlayer(ICMP).code) in [0,1,2,9,10,13]):
						etat = "Filtered"
				if packet1 != None:
					os = passiveOsDetection(packet1)
				elif packet2 != None:
					os = passiveOsDetection(packet2)
				if etat == "Open|Filtered" or "Filtered":
					service = servFingerprinting2(dstIp, dstPort)

				results[dstIp].append((dstPort, etat, service))
				if VERBOSE: print 'port', dstPort, etat

	except IOError as e:
		print(e)

	return results
	
def icmpPingSweep(ips):
	
	def ping(ip):
		probe = struct.pack('bbHHhd', 8, 0, 0, 0, 0, 2)
		sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
		try:
			sock.settimeout(1)
			sock.sendto(probe, (ip, 0))
			data, peer = sock.recvfrom(1024)
		except (socket.timeout, socket.error): 
			sock.close()
			return None
			
		sock.close()
		typ, code, checksum, id_, seq, payload = struct.unpack('bbHHhd', data)
		if peer[0] == ip:
			return ip
			
	pool = ThreadPool(256)
	results = pool.map(ping, ips)
	pool.close()
	pool.join()
	return filter(None, results)

def passiveOsDetection(packet):
	os = ""
	if int(packet.getlayer(IP).ttl) == 128:
		os = "Windows"
		if packet.haslayer(TCP):
			if int(packet.getlayer(TCP).window) == 8192:
				os = "Windows 7"
			elif int(packet.getlayer(TCP).window) == 65535:
				os = "Windows XP"
	elif int(packet.getlayer(IP).ttl) == 64:
		os = "Linux"
		
	if VERBOSE and os: print 'OS:', os
	
	return os

def versionServ(hostname, port, sock):
	if not sock:
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock.settimeout(2)
	data = ''
	try:
		sock.connect((hostname, port))
		data = sock.recv(2048)
		sock.close()
	except socket.timeout:
		print "timeout"
	except IOError as e:
		print e
	
	return data.strip()

def servFingerprinting2(dstIp, dstPort, sock=None): # TODO
	serv = ''
	print 'Fingerprinting'
	if dstPort == 80:
		res = None
		try:
			res = urlopen('http://' + dstIp + ":80", timeout=1)
			if VERBOSE: print 'Status code:', res.code
			serv = ''.join(res.info().getheaders('server')[:1])
			res.close()
		except URLError as e:
			if VERBOSE: print 'Status code:', e.code
			if e.code < 500:
				serv = ''.join(e.info().getheaders('server')[:1])
				if not serv:
					html = res.read()
					soup = BeautifulSoup(html, "lxml")
				#TODO: parse
			if not serv:
				serv = '[HTTP GET status {}]'.format(e.code)
		except socket.timeout:
			if VERBOSE: print 'timeout'
		except IOError as e:
			if VERBOSE: print e 
	
	if dstPort == 22: # SSH
		serv = versionServ(dstIp, dstPort, sock)
	if dstPort == 21: # FTP
		serv = versionServ(dstIp, dstPort, sock)
		
	if VERBOSE and serv: print 'service:', serv
	
	return serv
	
def servFingerprinting(dstIp, dstPort, sock=None): # TODO: faire un vrai fingerprinting
	serv = 'unknown'
	liste = []
	if dstPort == 80:
		try:
			res = requests.head('http://' + dstIp + ":80", timeout=1)
			url = 'http://' + dstIp + ":80"
			sock = urllib.urlopen(url)
			htmlSource = sock.read()
			sock.close()
			soup = BeautifulSoup.BeautifulSoup(htmlSource, "lxml")

			if res.status_code == 200:
				serv = res.headers["server"]
				sep1=serv.split(' ')
				sep2=sep1[0].split('/')
				liste.append(sep2[0])
				liste.append(sep2[1])
			else:
				serv = '[HTTP status {}]'.format(res.status_code)
				liste.append(serv)
		except requests.exceptions.Timeout:
			if VERBOSE: print "connection timeout"
		except ConnectionError:
			if VERBOSE: print "connection error"
	if dstPort == 22: # SSH
		serv = versionServ(dstIp, dstPort, sock)
		liste.append(serv)
	if dstPort == 21: # FTP
		serv = versionServ(dstIp, dstPort, sock)
		liste.append(serv)
	return liste


def searchCVE(service, version):
	"""Return a list of strings"""
	
	url = "https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword="+service+"+"+version
	res = urlopen(url)
	html = res.read()
	res.close()
	soup = BeautifulSoup(html, "lxml")
	
	listCVE = []
	for elt in soup.find_all('a', attrs={'href' : re.compile("^/cgi-bin/")}):
		listCVE.append(elt.get_text())
	return listCVE

def hostDiscovery(ipSpecs, dtype, privileged):
	ips = []
	isLan = all(isPrivate(ipSpec) for ipSpec in ipSpecs)
	
	if privileged == 2:
		if dtype == 'best':
			if isLan: dtype = ['arp', 'icmp_broadcast']
			else: dtype = ['icmp']
		elif 'icmp' in dtype and isLan: dtype = ['arp', 'icmp_broadcast']
	elif privileged == 1: dtype = ['icmp_lowpriv']

	if 'arp' in dtype:
		print 'Using ARP ping for host discovery'
		ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ipSpecs),retry=0,timeout=2, inter=.00001, verbose=VERBOSE)
		ips.extend(r.getlayer(ARP).psrc for _, r in ans if r.haslayer(ARP))
		for _, r in ans:
			if r.haslayer(ARP):
				conf.netcache.arp_cache[r[ARP].psrc] = r[ARP].hwsrc
		if VERBOSE:
			print "\narp cache:"; print conf.netcache.arp_cache
			print '\nips:', ips, '\n'
		
	if 'icmp_lowpriv' in dtype or ('icmp' in dtype and 'arp' not in dtype):
		print 'Using ICMP echo ping for host discovery'
		ips.extend(icmpPingSweep(handleIps(ipSpecs, True, True)))
	elif 'icmp' in dtype:
		print 'Using ICMP echo/timestamp ping for host discovery'
		ans, _ = sr(IP(dst=ipSpecs)/ICMP(type=[8,13]),timeout=2, inter=.00001, verbose=VERBOSE)
		ips.extend(r.getlayer(IP).src for _, r in ans if r.haslayer(IP))
	elif 'icmp_broadcast' in dtype:
		print 'Using ICMP echo/timestamp broadcast ping for host discovery'
		ans, _ = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/IP(dst=ipSpecs)/ICMP(type=[8,13]),timeout=2, inter=.00001, verbose=VERBOSE)
		ips.extend(r.getlayer(IP).src for _, r in ans if r.haslayer(IP))
		
	ips = sorted(set(ips))
	print 'Alive hosts:', ','.join(ips) or 'none'
	return list(ips)

def priviledgeLevel():
	try:
		socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
		
		return 2
	except socket.error as errRaw:
		if errRaw[0] in [errno.EPERM, errno.EACCES]:
			try:
				socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
				return 1
			except socket.error as errIcmp:
				print 'err icmp:', errIcmp
				if errIcmp[0] in [errno.EPERM, errno.EACCES]:
					pass#raise
			return 0
		print 'err raw:', errRaw
	raise RuntimeError('wtf?')

def toService(port, fingerprint='', fmt=True):
	if fingerprint not in ['', 'unknown']:
		return ' ' + fingerprint
	else:
		res = '?'
		with open('nmap-services', 'r') as servicesAssoc:
			servicesAssoc.seek(23)
			for line in servicesAssoc:
				if line.startswith('unknown'):
					continue
				portLineMatch = re.search(r'\s(' + str(port) + ')/', line[:25])
				if portLineMatch:
					firstSpaceIndex = re.search(r'\s', line[:25]).start()
					res = line[:firstSpaceIndex]
					break
		
		return '(' + res + ')' if fmt else res

# Server ports
# 1-1023: well-known, 1024-49151: vendor registered, 49152-65535: dynamic/private
VERY_COMMON_PORTS = [20, 21, 22, 23, 53, 80, 443, 8000, 8080, 8433] # FTP, SSH, Telnet, DNS, HTTP, HTTPS, HTTP Proxy, HTTP-alt, HTTPS-alt
OTHER_COMMON_PORTS = [81, 990, 1027, 3128, 8008, 8009, 8081, 8888, 32768, 32769] # HOSTS2, FTPS, IIS, Squid proxy, IBM HTTP, Apache JServ, various HTTP, Sun HTTP, IBM Filenet
DATABASE_PORTS = [1433, 1434, 1521, 1528, 2483, 2484, 3050, 3306, 5432] # MySQL, PostgreSQL, MSSQL, Oracle
EMAIL_PORTS = [25, 110, 143, 465, 587, 993, 995, 2525] # SMTP, POP3, IMAP, SMTPS, SMTP-alt, IMAPS, POPS, SMTP-alt
SHARED_SERVICE_PORTS = [111, 135, 137, 139, 445, 515, 548, 631, 873, 1025, 2049, 5357] # RPC bind, MSRPC, SMB, UNIX Printing, AFP/IP, CUPS, rsync, NFS or IIS, NFS, WSD-api
AUTH_PORTS = [88, 389, 464, 543, 544, 636, 2105, 3268, 3269] # Kerberos, LDAP
REMOTE_ADMIN_PORTS = [625, 3389, 5631, 5800, 5900] # Apple Xserver admin, MS RDP, pcanywhere-data, VNC HTTP, VNC
OTHER_COMMON2_PORTS = [1, 199, 512, 513, 514, 1723, 1900, 5000, 6000, 6001, 6002] # tcpmux, SNMP mux, exec, login, shell, PPTP, UPNP, X11
ROUTING_PORTS = [161, 162, 179, 1993, 1998, 2000] # SNMP, BGP, Cisco SNMP TCP, Cisco X.25 service, Cisco SCCP
VOIP_PORTS = [5060, 5061] # SIP, SIP-TLS
COMMON_PORTS = VERY_COMMON_PORTS + OTHER_COMMON_PORTS + SHARED_SERVICE_PORTS + EMAIL_PORTS \
	+ DATABASE_PORTS + AUTH_PORTS + REMOTE_ADMIN_PORTS + OTHER_COMMON2_PORTS
# Client ports
# 49152-65535 (Windows/BSD), 32768-61000 (Linux >= 2.4), 1024-4999 (Linux < 2.4)

if __name__ == "__main__":

	print """
+-------------------------------------------------------+
|   Bienvenue dans notre programme de scan de ports !   |
+-------------------------------------------------------+
"""

	parser = OptionParser()
	parser.add_option("-i", "--iface", dest="iface", type="string", help='interface to use')
	parser.add_option("-p", "--ports", dest="ports", type="string", default="very_common", help='ports to scan')
	parser.add_option("-d", "--discovery-type", dest="discoveryType", type="choice", choices=('best', 'arp', 'icmp', 'none'), default="best", help='discovery method')
	parser.add_option("-s", "--scantype", dest="scantype", type="string",
		metavar="(c) TCP Connect, (s) TCP SYN, (f) TCP FIN, (x) Xmas, (n) Null, (u) UDP",
		default="s", help='scan method')
	parser.add_option("-o", "--output", dest="output", type="string", default="", help='destination file for results')
	parser.add_option("-v", "--verbose", dest="verbose", action="count", default=0)

	(options, args) = parser.parse_args()

	if len(args) == 0:
		parser.print_help()
		print
		print 'Run `sysctl -w net.ipv4.ping_group_range="0 your_gid"` to allow unpriviledged users to use ICMP ping'
		print 'Run `setcap cap_net_raw=ep` as root on your python interpreter to allow raw sockets'
	else:
		VERBOSE = options.verbose
		conf.verb = VERBOSE >= 2
		#if VERBOSE == 1: logging.getLogger("scapy.runtime").setLevel(logging.DEBUG)
		if options.iface: conf.iface = options.iface
		conf.ipv6_enabled = False
		outFile = options.output
		
		# Check for priviledge level
		privileged = priviledgeLevel()
		if VERBOSE: print 'Priviledge level:', privileged
		if privileged == 0: exit()
		
		ipSpecs = args[0].split(',')
		ips = handleIps(ipSpecs, True, True)
		if VERBOSE >= 2: print 'Hosts to scan:', ips
		portStrings = options.ports.split(',')
		ports = handlePorts(portStrings)

		# Discover hosts before scanning ports
		if options.discoveryType != 'none':
			ips = hostDiscovery(ips, options.discoveryType, privileged)
		# No discovered ip in LAN
		if not ips and all(isPrivate(ipSpec) for ipSpec in ipSpecs): exit()
		
		# Create a structure to store results
		results = OrderedDict((ip, ['']) for ip in sorted(ips))
		
		if ips:
			# Launch scan
			if options.scantype == "c" or privileged < 2:
				results = tcp_connect(ips, ports, results)
			elif options.scantype == "s":
				results = parallelScan(syn, ips, ports, results)
				#results = tcp_syn3(ips, ports, results)
			elif options.scantype == "x":
				results = tcp_xmas(ips, port)
			elif options.scantype == "n":
				results = tcp_null(ips, port)
			elif options.scantype == "f":
				results = tcp_fin(ips, port)
			elif options.scantype == "u":
				results = udp(ips, ports, results)

		out = []
		for resultIP, resultData in results.items():
			# Sort port results
			resultData[1:] = sorted(resultData[1:])
			
			# Compute likely policy
			policy = 'closed'
			if len(resultData) > 0 and any(e[1] == 'filtered' for e in resultData[1:]):
				policy = 'filtered'
				
			# Generate output
			out.append('\nip: ' + resultIP + "\nOS: " + (resultData[0] or 'unknown') + "\nlikely policy: " + (policy or 'unknown') + '\nports: {} open'.format(sum(1 for dstPort, etat, _, _ in resultData[1:] if etat == 'open')))
			for dstPort, etat, service, cve in resultData[1:]:
				if etat != 'nores' and etat != policy:
					#out.append(str(dstPort) + " " + (etat or 'unknown') + toService(dstPort, service)) + " " + cve
					out.append(' '.join([str(dstPort), etat or 'unknown', toService(dstPort, service), cve]))
		
		print '''
+--------------------------------------------+
|  Report                                    |
+--------------------------------------------+'''
		print '\n'.join(out)
		if outFile: # Dump to file
			with open(outFile, 'a+') as dumpFile:
				dumpFile.write(strftime("%d %b %Y %H:%M:%S") + '\n')
				dumpFile.write(('#' if privileged else '$') + ' python ' + ' '.join(argv))
				dumpFile.write('\n'.join(out) + '\n---\n')
