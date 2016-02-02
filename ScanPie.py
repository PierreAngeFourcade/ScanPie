#!/usr/bin/env python
# -*- coding: Utf-8 -*-

from sys import exit, argv
import errno
from time import strftime
from optparse import OptionParser
from collections import OrderedDict
import logging
#from ares import CVESearch
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *
import requests
import urllib  
import socket
import bs4 as BeautifulSoup

def hasCIDR(ipSpec):
	return ipSpec.find('/') != -1

def isPrivate(ipSpec):
	return ipSpec.startswith('192.168') or ipSpec.startswith('10.') \
		or ipStrToInt(ipSpec.split('/')[0]) & 0xFFF00000 == 0xAC100000 \
		or ipSpec.startswith('127.')

def int32ToInts8(d):
	return [(d>>i*8)&0xFF for i in reversed(range(4))]

def ints8ToInt32(d):
	return sum(d[i]<<(3-i)*8 for i in range(4))

def ipStrToInt(ipStr):
	return ints8ToInt32(map(int, ipStr.split('.')))

def ipIntToStr(ipInt):
	return '.'.join(map(str, int32ToInts8(ipInt)))

def CIDRToMask(cidr):
	return int(('1'*cidr) + '0'*(32-cidr), 2)

def genIpCIDR(ipWithCidr):
	ip, cidr = ipWithCidr.split('/')
	cidr = int(cidr)
	#print 'CIDR:', cidr
	ipFields = list(map(int, ip.split('.')))
	ipInt = ints8ToInt32(ipFields)
	#print 'IP:', bin(ipInt), ipInt, ipFields
	mask = CIDRToMask(cidr)
	#print 'Mask:', bin(mask), mask, int32ToInts8(mask)
	curIp = mask & ipInt
	#print 'Network address:', bin(curIp), curIp, int32ToInts8(curIp)
	invMask = 2**(32-cidr)-1

	while curIp & invMask < invMask-1:
		curIp += 1
		#if not (curIp % invMask) % (invMask/32+1):
		#	print 'Current IP:', bin(curIp), curIp, int32ToInts8(curIp)
		yield '.'.join(map(str, int32ToInts8(curIp)))

def ipRange(ipStringRange):
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

	ips = []
	for i0 in range(*fieldRanges[0]):
		for i1 in range(*fieldRanges[1]):
			for i2 in range(*fieldRanges[2]):
				for i3 in range(*fieldRanges[3]):
					ips.append('{}.{}.{}.{}'.format(i0, i1, i2, i3))

	return ips

def handleIps(ipSpecs, handleCidr=False):
	ips = []
	for ipSpec in ipSpecs:
		if ipSpec.find('-') != -1:
			ips.extend(ipRange(ipSpec))
		elif handleCidr and hasCIDR(ipSpec):
			ips.extend(list(genIpCIDR(ipSpec)))
		elif ipSpec.startswith('127.'):
			ips.append('127.0.0.1')
		else:
			ips.append(ipSpec)
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
		elif portString == "1024_ports":
			ports.extend(BASIC_PORTS)
		elif portString == "all":
			ports.extend(ALL_PORTS)
		elif portString == "database":
			ports.extend(DATABASE_PORTS)
		elif portString =="email":
			ports.extend(EMAIL_PORTS)
		elif portString =="file_share":
			ports.extend(EMAIL_PORTS)
		elif portString =="email":
			ports.extend(EMAIL_PORTS)
		elif portString.find('-') != -1:
			ports.extend(port_range(portString))
		else:
			ports.append(int(portString))
	return ports

def tcp_connect(ips, ports, results, verbose=True):
	print "Réalisation d'un scan TCP connect\n"

	for dstIp in ips:
		for dstPort in ports:
			etat, service, os = 'unknown', 'unknown', 'unknown'

			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			s.settimeout(.5)
			try:
				s.connect((dstIp, dstPort))
				service = servFingerprinting(dstIp, dstPort, verbose, s)
				vuln = cve.search('apache')
				print vuln
				s.close()
				etat = 'open'
			except socket.timeout:
				etat = 'filtered'
			except socket.error:
				etat = 'closed'

			results[dstIp].append((dstPort, etat, service))
			if verbose: print 'ip', dstIp, 'port', dstPort, etat

	return results

def tcp_syn(ips, ports, results, verbose=True):
	print "Réalisation d'un scan TCP SYN\n"
	liste = []
	CVE = []
	try:
		srcPort = 80#RandShort()
		ans, _ = sr(IP(dst=ips)/TCP(sport=srcPort,dport=ports,flags="S"),
			timeout=2, verbose=verbose)

		for req, res in ans:
			etat, os, service, version = 'unknown','unknown', 'unknown', 'unknown'
			reqIp = req.getlayer(IP)
			if res == None:
				etat = 'filtered'
			else:
				if(res.haslayer(TCP)):
					resTcp = res.getlayer(TCP)
					if(resTcp.flags == 0x12):
						# Send RST to end connection properly
						send(IP(dst=reqIp.dst)/TCP(sport=resTcp.sport,dport=resTcp.dport,flags="AR"))
						etat = 'open'
						liste = servFingerprinting(reqIp.dst, resTcp.sport, verbose)
						#print liste
						if len(liste) > 1 :						
							service = liste[0]
							version = liste[1]
							CVE = searchCVE(service,version)
						elif len(liste) == 1:
							service = liste[0]
							version = ""
					elif (resTcp.flags == 0x14):
						etat = 'closed'
					else:
						print res.summary()
				elif(res.haslayer(ICMP)):
					if(int(res.getlayer(ICMP).type) == 3 and int(res.getlayer(ICMP).code) in [0,1,2,3,9,10,13]):
						etat = 'filtered'

				if os == 'unknown':
					os = passiveOsDetection(res)
					results[reqIp.dst][0] = os

			results[reqIp.dst].append((req.getlayer(TCP).dport, etat, service,version, CVE))
			if verbose: print 'ip', reqIp.dst, 'port', req.getlayer(TCP).dport, etat,service, version, CVE

	except IOError as e:
		print(e)

	return results

def tcp_xmas(ips, port, verbose=True):
	print "Réalisation d'un scan TCP Xmas\n"
	try:
		dstIp = ips
		srcPort = random.randint(1, 65535)
		dstPort = port

		packet = sr1(IP(dst=dstIp)/TCP(dport=dstPort,gflags="FPU"),timeout=5, verbose=verbose)
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


def tcp_fin(ips, port, verbose=True):
	print "Réalisation d'un scan FIN\n"
	try:
		dstIp = ips
		srcPort = random.randint(1,65535)
		dstPort = port

		packet = sr1(IP(dst=dstIp)/TCP(dport=dstPort,flags="F"),timeout=1, verbose=verbose)
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


def tcp_null(ips, port, verbose=True):
	print "Réalisation d'un scan NULL\n"
	try:
		dstIp = ips
		srcPort = random.randint(1,65535)
		dstPort = port

		packet = sr1(IP(dst=dstIp)/TCP(dport=dstPort,flags=""),timeout=1, verbose=verbose)
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

def udp(ips, ports, results, verbose):
	try:
		srcPort = RandShort()
		for dstIp in ips:
			os = None
			server = None
			if verbose: print 'ip', dstIp
			for dstPort in ports:
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
					service = servFingerprinting(dstIp, dstPort, verbose)

				results[dstIp].append((dstPort, etat, service))
				if verbose: print 'port', dstPort, etat

	except IOError as e:
		print(e)

	return results

def unpriviledgedPingICMP(ipSpecs):
	aliveIps = []
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
	s.settimeout(.1)
	for ip in handleIps(ipSpecs, True):
		p = struct.pack('bbHHhd', 8, 0, 0, 0, 0, 2)
		print ip
		try:
			s.sendto(p, (socket.gethostbyname(ip), 0))
			data, peer = s.recvfrom(1024)
		except socket.timeout: continue
		typ, code, checksum, id_, seq, payload = struct.unpack('bbHHhd', data)
		#print data, peer
		#print typ, code, checksum, id_, seq, payload
		if peer[0] == ip:
			aliveIps.append(ip)
	s.close()
	return aliveIps

def passiveOsDetection(packet):
	os = "unknown"
	if int(packet.getlayer(IP).ttl) == 128:
		os = "Windows"
		if packet.haslayer(TCP):
			if int(packet.getlayer(TCP).window) == 8192:
				os = "Windows 7"
			elif int(packet.getlayer(TCP).window) == 65535:
				os = "Windows XP"
	elif int(packet.getlayer(IP).ttl) == 64:
		os = "Linux"
	return os

def versionServ(hostname, port, sock):
	if not sock:
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock.settimeout(2)
	try:
		sock.connect((hostname, port))
		data = sock.recv(4096)
		sock.close()
	except socket.timeout:
		data = "timeout"
	return data.strip()

def servFingerprinting(dstIp, dstPort, verbose, sock=None): # TODO: faire un vrai fingerprinting
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
			if verbose: print "connection timeout"
		except ConnectionError:
			if verbose: print "connection error"
	if dstPort == 22: # SSH
		serv = versionServ(dstIp, dstPort, sock)
		liste.append(serv)
	if dstPort == 21: # FTP
		serv = versionServ(dstIp, dstPort, sock)
		liste.append(serv)
	if dstPort == 53: #DNS
		serv = versionBindDns(dstIp, dstPort)
		liste.append("bind")
		liste.append(serv)
	
	return liste

def versionBindDns(dstIp,dstPort):
	res = sr1(IP(dst=dstIp)/UDP(dport=dstPort)/DNS(rd=1,qd=DNSQR(qclass=3, qtype=16, qname='version.bind.')))
	return res[DNS].an.rdata

def searchCVE(service,version):
	url = "https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword="+service+"+"+version
	print url
	#print "url = "+url
	sock = urllib.urlopen(url) 
	htmlSource = sock.read()                            
	sock.close()                                        
	soup = BeautifulSoup.BeautifulSoup(htmlSource, "lxml")
	listCVE = []
	jointure = ""
	for el in soup.find_all('a', attrs={'href' : re.compile("^/cgi-bin/")}):
        	elt=el.get_text()
        	listCVE.extend(str(elt))
		listCVE.extend(" ")
		jointure="".join(listCVE)
	separateur=jointure.split(" ")
	taille = len(separateur)
	del separateur[taille-1]
	return separateur

def hostDiscovery(ipSpecs, dtype, verbose, privileged):
	ips = set()
	isLan = all(isPrivate(ipSpec) for ipSpec in ipSpecs)

	if privileged:
		if 'arp' in dtype or (dtype == 'best' and isLan): # ARP ping for LAN
			print 'Using ARP ping for host discovery'
			ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ipSpecs),filter='arp',timeout=2, verbose=verbose)
			ips.update({r.getlayer(ARP).psrc for _, r in ans if r.haslayer(ARP)})
		elif 'icmp' in dtype or dtype == 'best':
			print 'Using ICMP echo/timestamp ping for host discovery'
			ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/IP(dst=ipSpecs)/ICMP(type=[8,13]),filter='icmp',timeout=2, verbose=verbose)
			ips.update({r.getlayer(IP).src for _, r in ans if r.haslayer(IP)})
	else:
		print 'Using ICMP echo ping for host discovery'
		ips.update(unpriviledgedPingICMP(ipSpecs))

	ips = sorted(ips)
	print 'Alive hosts:', ','.join(ips) or 'none'
	return list(ips)

def isPrivileged():
	try:
		socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
		return True
	except socket.error as e:
		if e[0] == errno.EPERM:
			return False
		print e
	raise RuntimeError()

DATABASE_PORTS = [1433, 1521, 1528, 2483, 2484, 3050, 3306, 5432] # MySQL, PostgreSQL, MSSQL, Oracle
EMAIL_PORTS = [25, 110, 143, 465, 587, 993, 995, 2525] # SMTP, POP, IMAP
VERY_COMMON_PORTS = [20, 21, 22, 23, 53, 80, 443, 8080] # FTP, SSH, Telnet, DNS, HTTP
SHARED_SERVICES_PORTS = [111, 135, 137, 139, 445, 631, 2049] # RPC bind, MSRPC, SMB, CUPS, NFS
AUTH_PORTS = [88, 389, 636, 3268, 3269] # Kerberos, LDAP
OTHER_PORTS = [512, 513, 514, 3128] # exec, login, shell, Squid proxy
COMMON_PORTS = VERY_COMMON_PORTS + SHARED_SERVICES_PORTS + EMAIL_PORTS \
	+ AUTH_PORTS + DATABASE_PORTS + OTHER_PORTS
BASIC_PORTS = port_range("1-1024")
ALL_PORTS = port_range("1-65535")

if __name__=="__main__":

	print "---------------------------------------------------------"
	print "|   Bienvenue dans notre programme de scan de ports !   |"
	print "---------------------------------------------------------"

	parser = OptionParser()
	parser.add_option("-i", "--iface", dest="iface", type="string", help='interface to use')
	parser.add_option("-p", "--ports", dest="ports", type="string", default="very_common", help='ports to scan')
	parser.add_option("-d", "--discovery-type", dest="discoveryType", type="string", default="best", help='discovery method')
	parser.add_option("-s", "--scantype", dest="scantype", type="string",
		metavar="(c) TCP Connect, (s) TCP SYN, (f) TCP FIN, (x) Xmas, (n) Null, (u) UDP",
		default="s", help='scan method')
	parser.add_option("-o", "--output", dest="output", type="string", default="", help='destination file for results')
	parser.add_option("-v", "--verbose", dest="verbose", action="count", default=0)

	(options, args) = parser.parse_args()
	verbose = options.verbose

	if len(args) == 0:
		parser.print_help()
		'Use sysctl -w net.ipv4.ping_group_range="0 your_gid" to allow unpriviledged users to use ICMP ping'
	else:
		conf.verb = verbose > 1
		if options.iface: conf.iface = options.iface
		conf.ipv6_enabled = False
		privileged = isPrivileged()
		outFile = options.output

		ipSpecs = args[0].split(',')
		ipSpecs = handleIps(ipSpecs)
		portStrings = options.ports.split(',')
		ports = handlePorts(portStrings)

		ips = hostDiscovery(ipSpecs, options.discoveryType, verbose, privileged)

		results = OrderedDict((ip, ['unknown']) for ip in sorted(ips))

		# Launch scan
		if options.scantype == "c":
			results = tcp_connect(ips, ports, results, verbose)
		elif options.scantype == "s":
			results = tcp_syn(ips, ports, results, verbose)
		elif options.scantype == "x":
			results = tcp_xmas(ips, port, verbose)
		elif options.scantype == "n":
			results = tcp_null(ips, port, verbose)
		elif options.scantype == "f":
			results = tcp_fin(ips, port, verbose)
		elif options.scantype == "u":
			results = udp(ips, ports, results, verbose)

		out = []
		for resultIP, resultData in results.items():
			policy = 'closed'
			if any(e[1] == 'filtered' for e in resultData[1:]):
				policy = 'filtered'
			out.append('\nip: ' + resultIP + "\nOS: " + resultData[0] + "\nlikely policy: " + policy)
			for dstPort, etat, service, version, CVE in resultData[1:]:
				if etat != policy:
					out.append(str(dstPort) + " " + etat + " " + str(service) + " " + str(version) + " " + str(CVE))

		print '\n'.join(out)
		if outFile:
			with open(outFile, 'a+') as dumpFile:
				dumpFile.write(strftime("%d %b %Y %H:%M:%S") + '\n')
				dumpFile.write(('#' if privileged else '$') + ' python ' + ' '.join(argv))
				dumpFile.write('\n'.join(out) + '\n---\n')
