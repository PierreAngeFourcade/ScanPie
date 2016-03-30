#!/usr/bin/env python
# -*- coding: Utf-8 -*-

from sys import exit, argv
import errno
from time import time, strftime
from optparse import OptionParser
from collections import OrderedDict
import itertools
import re
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

import threading
from threading import Thread, Lock
from Queue import Queue, Empty
from multiprocessing.dummy import Pool as ThreadPool

from ipaddress import ip_address, ip_network, IPv4Address, IPv6Address, IPv4Network, IPv6Network
import socket
import struct
from fcntl import ioctl
from scapy.all import *

import cfg
from cfg import PRINT, ERROR, WARN, INFO, PEDANTIC, STATUS, DEBUG
from fingerprint import *
import visualization


class ScanResults(OrderedDict):
	
	def __init__(self, dict_):
		OrderedDict.__init__(self, dict_)
		self.osByIp = {}

	@classmethod
	def create(klass, ips, ports):
		return klass({ip: {port: {} for port in sorted(ports)} for ip in sorted(ips)})
		
	def __str__(self):
		return OrderedDict.__str__(self) + str(self.osByIp)
		
	def yamlRepr(self):
		out = []
		for ip in self:
			out.append('{}:'.format(ip))
			out.append('  OS: {}'.format(self.getOS(ip)))
			for port in self[ip]:
				scanLine = ', '.join('{} {}'.format(k,v) for k,v in self[ip][port].iteritems() if v)
				out.append('  {}: {}'.format(port, scanLine))
		return '\n'.join(out)
		
	def getOS(self, ip):
		return self.osByIp.get(ip, '')
		
	def setOS(self, ip, os):
		self.osByIp[ip] = os
	
	def add(self, key, val):
		if not key in self:
			self[key] = ['']
		self[key].append(val)
		
	def updateFromStructure(self, structure):
		for ip, os, line in structure:
			self.add(ip, line)
			if not self[ip][0]:
				self[ip][0] = os
				
	def os(self, key):
		return self[key][0]

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
	ipInt = ipStrToInt(socket.gethostbyname(ip))
	mask = prefixToMask(prefix)
	#DEBUG('IP: %s %s Mask: %s %s', bin(ipInt), ipInt, bin(mask), mask)
	curIp = mask & ipInt
	#DEBUG('Network address: %s %s %s', bin(curIp), curIp, int32ToInts8(curIp))
	invMask = 2**(32-prefix)-1

	while curIp & invMask < invMask-1:
		curIp += 1
		#if not (curIp % invMask) % (invMask/32+1):
		#	DEBUG('Current IP: %s %s %s', bin(curIp), curIp, int32ToInts8(curIp))
		yield ipIntToStr(curIp)

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
				ip_network(unicode(networkToHosts(ipSpec).next())) # Validation
			except ValueError: 
				ERROR('Error: malformed network ip')
				continue
			if handlePrefix: ips.extend(networkToHosts(ipSpec))
			else: ips.append(ipSpec)
		elif ipSpec.find('-') != -1 and handleRange:
			# TODO: validation
			ips.extend(ipv4Range(ipSpec))
		else:
			try:
				ip_address(unicode(socket.gethostbyname(ipSpec))) # Validation
			except:
				ERROR('Error: malformed ip')
				continue
			ips.append(ipSpec)
			
	# Bugs when sending packets to self, so discard
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
			ports.extend(cfg.COMMON_PORTS)
		elif portString == "very_common":
			ports.extend(cfg.VERY_COMMON_PORTS)
		elif portString == "database":
			ports.extend(cfg.DATABASE_PORTS)
		elif portString == "email":
			ports.extend(cfg.EMAIL_PORTS)
		elif portString == "shared_service":
			ports.extend(cfg.SHARED_SERVICE_PORTS)
		elif portString == "auth":
			ports.extend(cfg.AUTH_PORTS)
		elif portString == "other":
			ports.extend(cfg.OTHER_PORTS)
		elif portString == "voip":
			ports.extend(cfg.VOIP_PORTS)
		elif portString == "http":
			ports.extend(cfg.HTTP_PORTS + cfg.HTTPS_PORTS)
		elif portString.find('-') != -1:
			ports.extend(port_range(portString))
		else:
			try:
				ports.append(int(portString))
			except ValueError:
				ERROR('Error: Invalid port, port category or port range.')
				exit(-1)
	return ports
	

def tcp_connect(ips, ports, results):
	PRINT("\nRéalisation d'un scan TCP connect\n")
	
	def scan(structure):
		results, dstIp, dstPort = structure
		etat, service, os = '', '', ''

		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.settimeout(2)
		try:
			sock.connect((dstIp, dstPort))
			service = servFingerprinting(dstIp, dstPort, sock)
			sock.close()
			etat = 'open'
		except socket.timeout:
			etat = 'filtered'
		except socket.error:
			etat = 'closed'

		results[dstIp].append((dstPort, etat, service))
		INFO('ip %s port %s %s', dstIp, dstPort, etat)

	upper, lower = max(len(ips), len(ports)), min(len(ports), len(ips))
	INFO("pool base: %s", min(upper * min(4, lower), 1024))
	pool = ThreadPool(min(upper * min(4, lower), 1024))
	pool.map(scan, [(results, ip, port) for port in ports for ip in ips])
	pool.close()
	pool.join()
	return results

def queuedScan(scan, queue, ports, results):
	while True:
		ip = queue.get()
		try:
			res = scan(ip, ports)
			results[ip] = res
		except IOError as e:
			ERROR('%s', e); raise
		finally:
			queue.task_done()

def parallelScan(scan, ips, ports, results):

	poolSize = min(len(ips), 256)
	INFO("Pool size: %s", poolSize)
	queue = Queue()
	
	for i in range(poolSize):
		worker = Thread(target=queuedScan, args=(scan, queue, ports, results))
		worker.daemon = True
		worker.start()
	
	for ip in ips:
		queue.put(ip)
	queue.join()
	
	return results

def syn(ip, ports):
	result = ['']
	ans, _ = sr(IP(dst=ip)/TCP(sport=80,dport=ports,flags="S"), \
	inter=.1, retry=1, timeout=5, verbose=(cfg.VERBOSE==2))
		
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
					service = servFingerprinting(reqIp.dst, resTcp.sport)
					if service and not service.startswith('[') and service.count('/') > 0:
						cve = ' '.join(searchCVE(*service.split('/', 1)))
				elif (resTcp.flags == 0x14):
					etat = 'closed'
				else:
					INFO('Weird packet: %s', res.summary())
			elif(res.haslayer(ICMP)):
				if(int(res.getlayer(ICMP).type) == 3 and int(res.getlayer(ICMP).code) in [0,1,2,3,9,10,13]):
					etat = 'filtered'

			if result[0] == '':
				result[0] = passiveOsDetection(res)

		result.append((req.getlayer(TCP).dport, etat, service, cve))
		INFO('ip %s port %s %s %s', reqIp.dst, req.getlayer(TCP).dport, etat, cve)
		
	return result
	
def parallelScan2(scan, ips, ports, results): # one 

	poolSize = min(len(ips), 256)
	INFO("Pool size: %s", poolSize)
	queue = Queue()
	
	workers = []
	for i in range(poolSize):
		worker = Thread(target=queuedScan2, args=(scan, queue, results))
		worker.daemon = True
		worker.start()
		workers.append(worker)
	
	for port in ports:
		for ip in ips:
			queue.put((ip, port))
	queue.join()
	
	return results
	
def queuedScan2(scan, queue, results):
	sock = conf.L3socket(filter=None, iface=conf.iface, nofilter=1)
	while True:
		ip, port = queue.get()
		try:
			scan(ip, port, results, sock)
		except IOError as e:
			ERROR('%s', e); raise
		finally:
			queue.task_done()

def syn2(ip, port, results, sock):
	ans, _ = sndrcv(sock, IP(dst=ip)/TCP(sport=80,dport=port,flags="S"), timeout=2, retry=1, verbose=(cfg.VERBOSE==2))
	res = ans[0][1] if len(ans) else None
	
	etat, service, cve = '', '', ''
	if res == None:
		etat = 'nores'
	else:
		if(res.haslayer(TCP)):
			resTcp = res.getlayer(TCP)
			if(resTcp.flags == 0x12):
				# Kernel send RST to end connection
				etat = 'open'
				service = servFingerprinting(ip, port)
				if service and not service.startswith('[') and service.count('/') > 0:
					cveUrl, cveList = searchCVE(*service.split('/', 1))
					cve = cveUrl
					if cfg.VERBOSE:
						cve += '\n' + ' '.join(cveList)
			elif (resTcp.flags == 0x14):
				etat = 'closed'
			else:
				INFO('Weird packet: %s', res.summary())
		elif(res.haslayer(ICMP)):
			if(int(res.getlayer(ICMP).type) == 3 and int(res.getlayer(ICMP).code) in [0,1,2,3,9,10,13]):
				etat = 'filtered'

		if results[ip][0] == '':
			results[ip][0] = passiveOsDetection(res)

	results[ip].append((port, etat, service, cve))
	INFO('ip %s port %s %s %s', ip, port, etat, cve)
	
def parallel(poolSize, func, input_, **opts):
	
	PEDANTIC('Opts: %s\nInputs: %s', opts, input_)
	inQueue, outQueue = Queue(), Queue()
	
	for i in range(poolSize):
		worker = Thread(target=queued, args=(func, inQueue, outQueue, opts))
		worker.daemon = True
		worker.start()
	
	for e in input_:
		inQueue.put(e)
	try:
		inQueue.join()
	except KeyboardInterrupt:
		pass
		
	res = []
	while True:
		try: res.append(outQueue.get_nowait())
		except Empty: break
		
	return res
	
def queued(func, inQueue, outQueue, opts):
	kwargs = {}
	if 'createSock' in opts:
		kwargs['sock'] = conf.L3socket(filter=None, iface=conf.iface, nofilter=1)
	thisThread = threading.currentThread()
	while True:
		try:
			#INFO('[%s]', thisThread.name)
			args = inQueue.get()
			res = func(*args, **kwargs)
			if res is not None:
				if 'associate' in opts: outQueue.put((args, res))
				else: outQueue.put(res)
		except IOError as e:
			ERROR('%s', e); raise
		finally:
			inQueue.task_done()
			
def fingerprintOpenPort(ip, port):
	service = servFingerprinting(ip, port)
	cve = ''
	if service and not service.startswith('[') and service.count('/') > 0:
		cveUrl, cveList = searchCVE(*service.split('/', 1))
		INFO('CVE: %r %r', cveUrl, cveList)
		cve = cveUrl
		if cfg.VERBOSE:
			cve += ' ' + ' '.join(cveList)
	return service, cve
			
def syn3(ips, ports, results):
	poolSize = min(int(len(ips)**.5)+2, 20)
	INFO("Pool size: %s", poolSize)
	
	def scan(ip, port, sock):
		ans, unans = sndrcv(sock, IP(dst=ip)/TCP(sport=80,dport=port,flags="S"), timeout=2, retry=-1, verbose=(cfg.VERBOSE==2))
		DEBUG('ip %s port %s (%s)', ip, port, 'res' if ans else 'nores')
		return ans[0] if ans else (unans[0], None)
	
	answers = parallel(poolSize, scan, itertools.product(ips, ports), createSock=True)
	
	for req, res in answers:
		etat, service, cve = '', '', ''
		ip = req.getlayer(IP).dst
		
		if res == None:
			etat = 'nores'
		else:
			if(res.haslayer(TCP)):
				resTcp = res.getlayer(TCP)
				if(resTcp.flags == 0x12):
					# Kernel send RST to end connection
					etat = 'open'
				elif (resTcp.flags == 0x14):
					etat = 'closed'
				else:
					INFO('Weird packet: %s', res.summary())
			elif(res.haslayer(ICMP)):
				if(int(res.getlayer(ICMP).type) == 3 and int(res.getlayer(ICMP).code) in [0,1,2,3,9,10,13]):
					etat = 'filtered'
			
			if results.getOS(ip) == '':
				results.setOS(ip, passiveOsDetection(res))
			
		results[ip][req.getlayer(TCP).dport]['etat'] = etat
		#INFO('ip %s port %s %s', ip, req.getlayer(TCP).dport, etat)
	
	openPorts = [(ip, port) for ip in results for port in results[ip] if results[ip][port]['etat'] == 'open']
	DEBUG('Open ports: %s', openPorts)
	
	fingerprints = parallel(poolSize, fingerprintOpenPort, openPorts, associate=True)
	
	for keys, res in fingerprints:
		ip, port = keys
		service, cve = res
		for port_ in results[ip]:
			if port_ == port:
				results[ip][port]['service'] = service
				results[ip][port]['cve'] = cve
	
	return results

def tcp_syn(ips, ports, results):
	PRINT("\nRéalisation d'un scan TCP SYN\n")
	
	srcPort = 80#RandShort()
	try:
		ans, _ = sr(IP(dst=ips)/TCP(sport=srcPort,dport=ports,flags="S"),
			timeout=2, retry=1, inter=.1, verbose=(cfg.VERBOSE==2))
		
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
						service = servFingerprinting(reqIp.dst, resTcp.sport)
					elif (resTcp.flags == 0x14):
						etat = 'closed'
					else:
						INFO('Weird packet: %s', res.summary())
				elif(res.haslayer(ICMP)):
					if(int(res.getlayer(ICMP).type) == 3 and int(res.getlayer(ICMP).code) in [0,1,2,3,9,10,13]):
						etat = 'filtered'

				if results[reqIp.dst][0] == '':
					results[reqIp.dst][0] = passiveOsDetection(res)

			results[reqIp.dst].append((req.getlayer(TCP).dport, etat, service, ''))
			INFO('ip %s port %s %s', reqIp.dst, req.getlayer(TCP).dport, etat)

	except IOError as e:
		ERROR('%s', e)

	return results

def tcp_syn2(ips, ports, results):
	PRINT("\nRéalisation d'un scan TCP SYN\n")
	
	def scan(queue, lock, results, ports):
		sock = conf.L3socket(filter=None, iface=conf.iface, nofilter=1)
		try:
			while True:
				ip = queue.get()
				try:
					ans, _ = sndrcv(sock, IP(dst=ip)/TCP(sport=80,dport=ports,flags="S"), \
					timeout=2, inter=.1, retry=1, verbose=(cfg.VERBOSE==2))
					
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
									service = servFingerprinting(ip, port)
								elif resTcp.flags == 0x14:
									etat = 'closed'
								else:
									INFO('Weird packet: %s', res.summary())
							elif res.haslayer(ICMP):
								if int(res.getlayer(ICMP).type) == 3 and int(res.getlayer(ICMP).code) in [0,1,2,3,9,10,13]:
									etat = 'filtered'

							if results[ip][0] == '':
								results[ip][0] = passiveOsDetection(res)

						with lock:
							results[ip].append((port, etat, service, ''))
						INFO('ip %s port %s %s', ip, port, etat)

				except IOError as e:
					ERROR('%s', e); raise
				finally:
					queue.task_done()
		finally:
			sock.close()

	upper, lower = max(len(ips), len(ports)), min(len(ports), len(ips))
	poolSize = min(len(ips), 256)#min(upper * min(4, lower), 1024)
	INFO("Pool size: %s", poolSize)
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
	PRINT("\nRéalisation d'un scan TCP Xmas\n")
	try:
		dstIp = ips
		srcPort = random.randint(1, 65535)#RandShort()
		dstPort = port

		packet = sr1(IP(dst=dstIp)/TCP(dport=dstPort,gflags="FPU"),timeout=5, verbose=cfg.VERBOSE)
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
		ERROR('%s', e)

def tcp_fin(ips, port):
	PRINT("\nRéalisation d'un scan FIN\n")
	try:
		dstIp = ips
		srcPort = random.randint(1,65535)
		dstPort = port

		packet = sr1(IP(dst=dstIp)/TCP(dport=dstPort,flags="F"),timeout=1, verbose=cfg.VERBOSE)
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
		ERROR('%s', e)

def tcp_null(ips, port):
	PRINT("\nRéalisation d'un scan NULL\n")
	try:
		dstIp = ips
		srcPort = random.randint(1,65535)
		dstPort = port

		packet = sr1(IP(dst=dstIp)/TCP(dport=dstPort,flags=""),timeout=1, verbose=cfg.VERBOSE)
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
		ERROR('%s', e)

def udp(ips, ports, results):
	PRINT("\nRéalisation d'un scan UDP\n")
	try:
		srcPort = RandShort()
		for dstPort in ports:
			os, server = '', ''
			for dstIp in ips:
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
					service = servFingerprinting(dstIp, dstPort)

				results[dstIp].append((dstPort, etat, service))
				INFO('ip %s port %s %s', dstIp, dstPort, etat)

	except IOError as e:
		ERROR('%s', e)

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

def hostDiscovery(ipSpecs, dtype, privileged):
	ips = []
	isLan = all(isPrivate(ipSpec) for ipSpec in ipSpecs)
	
	if privileged == 2:
		if dtype == 'best':
			if isLan: dtype = ['arp', 'icmp_broadcast', 'syn']
			else: dtype = ['icmp', 'syn']
		elif 'icmp' in dtype and isLan: dtype = ['arp', 'icmp_broadcast']
	elif privileged == 1: dtype = ['icmp_lowpriv']

	if 'syn' in dtype:
		PRINT('Using TCP SYN ping for host discovery')
		ans, _ = sr(IP(dst=ipSpecs)/TCP(sport=80, dport=[80,445]),timeout=1, inter=.0005, verbose=cfg.VERBOSE)
		discovered = [req.getlayer(IP).dst for req, res in ans if res.haslayer(IP)]
		ips.extend(discovered)
		INFO('\ndiscovered ips: %s\n', discovered)
	if 'arp' in dtype:
		PRINT('Using ARP ping for host discovery')
		ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ipSpecs),retry=0,timeout=2, inter=.001, verbose=cfg.VERBOSE)
		discovered = [req.getlayer(ARP).pdst for req, res in ans if res.haslayer(ARP)]
		ips.extend(discovered)
		for _, res in ans:
			if res.haslayer(ARP):
				conf.netcache.arp_cache[res[ARP].psrc] = res[ARP].hwsrc
		INFO("\narp cache:\n%s", conf.netcache.arp_cache)
		INFO('\ndiscovered ips: %s\n', discovered)
		
	if 'icmp_lowpriv' in dtype:
		PRINT('Using ICMP echo ping for host discovery')
		discovered = [icmpPingSweep(handleIps(ipSpecs, True, True))]
		ips.extend(discovered)
		INFO('\ndiscovered ips: %s\n', discovered)
	elif 'icmp' in dtype:
		PRINT('Using ICMP echo/timestamp ping for host discovery')
		ans, _ = sr(IP(dst=ipSpecs)/ICMP(type=[8,13]),timeout=2, inter=.001, verbose=cfg.VERBOSE)
		discovered = [req.getlayer(IP).dst for req, res in ans if res.haslayer(IP)]
		ips.extend(discovered)
		INFO('\ndiscovered ips: %s\n', discovered)
	elif 'icmp_broadcast' in dtype:
		PRINT('Using ICMP echo/timestamp broadcast ping for host discovery')
		ans, _ = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/IP(dst=ipSpecs)/ICMP(type=[8,13]),timeout=2, inter=.001, verbose=cfg.VERBOSE)
		discovered = [req.getlayer(IP).dst for req, res in ans if res.haslayer(IP)]
		ips.extend(discovered)
		INFO('\ndiscovered ips: %s\n', discovered)
		
	ips = sorted(set(ips))
	PRINT('%s hosts discovered: %s', len(ips), ','.join(ips) or 'none')
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
				DEBUG('err icmp: %s', errIcmp)
				if errIcmp[0] in [errno.EPERM, errno.EACCES]:
					pass#raise
			return 0
		DEBUG('err raw: %s', errRaw)
	raise RuntimeError('wtf?')

def generateReport(results):
	out = []
	for ip in results: 
		# Sort port results
		
		# Compute likely policy
		policy = 'closed'
		if any(results[ip][port]['etat'] == 'filtered' for port in results[ip]):
			policy = 'filtered'
			
		# Generate output
		out.append('\nip: ' + ip)
		out.append('passive OS detection: ' + (results.getOS(ip) or 'unknown'))
		out.append('likely policy: ' + (policy or 'unknown'))
		out.append('ports: {} open'.format(sum(1 for portRes in results[ip].itervalues() if portRes['etat'] == 'open')))
		for port, portRes in results[ip].iteritems():
			etat = portRes['etat']
			if etat != 'nores' and etat != policy:
				out.append(' '.join([str(port), etat or 'unknown', toService(port, portRes['service']), portRes['cve']]))
	return out

if __name__ == "__main__":

	PRINT("""
+-------------------------------------------------------+
|   Bienvenue dans notre programme de scan de ports !   |
+-------------------------------------------------------+
""")

	parser = OptionParser()
	parser.add_option("-i", "--iface", dest="iface", type="string", help='interface to use')
	parser.add_option("-p", "--ports", dest="ports", type="string", default="very_common", help='ports to scan')
	parser.add_option("-d", "--discovery-type", dest="discoveryType", type="choice", choices=('best', 'arp', 'icmp', 'none'), default="best", help='discovery method')
	parser.add_option("-s", "--scantype", dest="scantype", type="string",
		metavar="(c) TCP Connect, (s) TCP SYN, (f) TCP FIN, (x) Xmas, (n) Null, (u) UDP, (none) no port scan",
		default="s", help='scan method')
	parser.add_option("-f", "--force-portscan", dest="forceScan", action="store_true", default=False, help="Scan even if discovery didn't find any alive host")
	parser.add_option("-o", "--output", dest="output", type="string", default="", help='destination file for results')
	parser.add_option("-v", "--verbose", dest="verbose", action="count", default=0)

	(options, args) = parser.parse_args()

	if len(args) == 0:
		parser.print_help()
		PRINT('\nRun `sysctl -w net.ipv4.ping_group_range="0 your_gid"` to allow unpriviledged users to use ICMP ping')
		PRINT('Run `setcap cap_net_raw=ep` as root on your python interpreter to allow raw sockets')
	else:
		cfg.VERBOSE = options.verbose
		conf.verb = cfg.VERBOSE >= 2
		#if cfg.VERBOSE == 1: logging.getLogger("scapy.runtime").setLevel(logging.DEBUG)
		if options.iface: conf.iface = options.iface
		conf.ipv6_enabled = False
		outFile = options.output
		
		# Check priviledge level
		privileged = priviledgeLevel()
		INFO('Priviledge level: %s', privileged)
		if privileged == 0: exit()
		
		ipSpecs = args[0].split(',')
		ips = handleIps(ipSpecs, True, True)
		STATUS('Hosts to scan: %s', ips)
		portStrings = options.ports.split(',')
		ports = handlePorts(portStrings)

		# Discover hosts before scanning ports
		if options.discoveryType != 'none':
			ips = hostDiscovery(ips, options.discoveryType, privileged)
			
		# Quit if no discovered ip for LAN scan
		if not options.forceScan and not ips and all(isPrivate(ipSpec) for ipSpec in ipSpecs): exit()
		
		# Create a structure to store results
		results = ScanResults.create(ips, ports)
		
		if ips:
			# Launch scan
			if options.scantype == "c" or privileged < 2:
				results = tcp_connect(ips, ports, results)
			elif options.scantype == "s":
				#results = tcp_syn(ips, ports, results)
				#results = parallelScan2(syn2, ips, ports, results)
				results = syn3(ips, ports, results)
			elif options.scantype == "x":
				results = tcp_xmas(ips, port)
			elif options.scantype == "n":
				results = tcp_null(ips, port)
			elif options.scantype == "f":
				results = tcp_fin(ips, port)
			elif options.scantype == "u":
				results = udp(ips, ports, results)
			else: exit()
		DEBUG('Results:\n%s', results.yamlRepr())
		
		out = generateReport(results)
		PRINT('''
+--------------------------------------------+
|  Report                                    |
+--------------------------------------------+''')
		PRINT('\n'.join(out))
		if outFile: # Dump to file
			with open(outFile, 'a+') as dumpFile:
				dumpFile.write(strftime("%d %b %Y %H:%M:%S") + '\n')
				dumpFile.write(('#' if privileged else '$') + ' python ' + ' '.join(argv))
				dumpFile.write('\n'.join(out) + '\n---\n')
		
		visualization.drawAndExport(visualization.toGraph(results))
