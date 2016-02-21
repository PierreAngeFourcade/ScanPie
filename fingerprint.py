#!/usr/bin/env python
# -*- coding: Utf-8 -*-

from sys import exit
import errno
import re
from bs4 import BeautifulSoup
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from urllib2 import urlopen, URLError
import socket
from scapy.all import *

import ScanPie as sp

def servFingerprinting(dstIp, dstPort, sock=None): # TODO
	serv = ''
	if sp.VERBOSE: print 'Fingerprinting', dstIp, dstPort
	if dstPort == 80: # HTTP
		serv = httpServ(dstIp, dstPort)
	if dstPort == 22: # SSH
		banner = versionServ(dstIp, dstPort, sock)
		serv = '/'.join(ssh_vers(banner))
	if dstPort == 21: # FTP
		banner = versionServ(dstIp, dstPort, sock)
		serv = '/'.join(ftp_vers(banner))
	if dstPort == 53: # DNS (Que bind faut pas déconner) 
		serv = "Bind/" + versionBindDns(dstIp,dstPort)
	
	print 'sp.VERBOSE:', sp.VERBOSE
	if sp.VERBOSE and serv: print 'service:', serv
	
	return serv
	
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
	
def httpServ(dstIp, dstPort=80):
	res = None
	try:
		res = urlopen('http://' + dstIp + ":" + str(dstPort), timeout=1)
		if sp.VERBOSE: print 'Status code:', res.code
		serv = ''.join(res.info().getheaders('server')[:1])
		res.close()
	except URLError as e:
		if sp.VERBOSE: print 'Status code:', e.code
		if e.code < 500:
			serv = ''.join(e.info().getheaders('server')[:1])
			if not serv:
				html = res.read()
				soup = BeautifulSoup(html, "lxml")
				# TODO: test parsing
				print soup.address
				list_serv = http_vers(soup.address)
				serv = '/'.join(list_serv)
		if not serv:
			serv = '[HTTP GET status {}]'.format(e.code)
	except socket.timeout:
		if sp.VERBOSE: print 'timeout'
	except IOError as e:
		if sp.VERBOSE: print e 
		
	return serv
	
def http_vers(chaine):
	list_http = ["Apache","Apache Tomcat","busybox httpd","Microsoft-IIS","lighttpd","nginx","Sun-Java-System-Web-Server", "Zeus"]
	liste_serv = []
	#chaine = "Microsoft-IIS/2.4.9"
	for elt in list_http:
		researchServ = re.search(elt,chaine)
		if re.search(elt, chaine, re.I):
			serveur = elt
			researchVer=re.search("/([0-9.]+[0-9.]+[0-9])",chaine)
			version=researchVer.group(0)
			print "version: " + version[1:]
			break
			liste_serv.append(serveur)
			liste_serv.append(version[1:])
	return liste_serv

def ftp_vers(chaine):
	dict_ftp = {"FileZilla Server":"[0-9.]+[0-9.]+[0-9]* | [0-9.]+[0-9.]+[0-9a]","vsFTPd":"(.+ \d+\.\d+\.\d+)","ProFTPD":"[0-9.]+[0-9.]+[0-9.]+[0-9]rc","WeOnlyDo-wodFTPD":"[0-9.]+[0-9.]+[0-9]*"}
	liste_serv = []
	for service, regex in dict_ftp.items():
		researchVer = re.search(regex, chaine, re.I)
		if re.search(service, chaine, re.I):
			serveur = service
			if serveur is "WeOnlyDo-wodFTPD":
				serveur = "freeFTPd"
				
			if researchVer:
				version = researchVer.group(0)
				version = version.replace("(","").replace(")","")
				break
			liste_serv.append(serveur)
			liste_serv.append(version)
	return liste_serv
				
def ssh_vers(chaine):
	dict_ssh = {"OpenSSH":"_[0-9.]+[0-9.]+[0-9]+p+[0-9]","WeOnlyDo-wodSSHD":" [0-9.]+[0-9.]+[0-9]*"}
	liste_serv = []
	for service,regex in dict_ssh.items():
		researchVer = re.search(regex,chaine,re.I)
		if re.search(service,chaine,re.I):
			serveur = service
			if serveur is "WeOnlyDo-wodSSHD":
				serveur = "freeSSHd"
			
			if researchVer:
				version= researchVer.group(0)
				break
			liste_serv.append(serveur)
			liste_serv.append(version[1:])
	return liste_serv
		
def versionBindDns(dstIp,dstPort):
	res = sr1(IP(dst=dstIp)/UDP(dport=dstPort)/DNS(rd=1,qd=DNSQR(qclass=3, qtype=16, qname='version.bind.')))
	return res[DNS].an.rdata.strip()

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
		
	if sp.VERBOSE and os: print 'OS:', os
	
	return os
	
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
