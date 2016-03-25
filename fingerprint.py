#!/usr/bin/env python
# -*- coding: Utf-8 -*-

from sys import exit
import errno
import re, string
from bs4 import BeautifulSoup
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from urllib2 import urlopen, URLError
import requests
import socket
from scapy.all import *

import cfg
from cfg import PRINT, ERROR, WARN, INFO, STATUS, DEBUG

def servFingerprinting(dstIp, dstPort, sock=None): # TODO
	serv = ''
	INFO('Fingerprinting: %s %s', dstIp, dstPort)
	try:
		if dstPort in cfg.HTTP_PORTS + cfg.HTTPS_PORTS: # HTTP(S)
			serv = httpServ(dstIp, dstPort)
		if dstPort == 22: # SSH
			banner = versionServ(dstIp, dstPort, sock)
			serv = '/'.join(ssh_vers(banner))
			if serv == '':
				serv = banner
		if dstPort == 21: # FTP
			banner = versionServ(dstIp, dstPort, sock)
			serv = '/'.join(ftp_vers(banner))
			if serv == '':
				serv = banner
		if dstPort == 53: # DNS (Bind seulement) 
			serv = "Bind/" + versionBindDns(dstIp, dstPort)
	except Exception as e:
		INFO('Fingerprinting error: %s', e)
		DEBUG('%s', e.__dict__)
	
	serv = ''.join(c for c in serv if c in string.printable)
	if serv: INFO('Service: %r', serv)
	
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
		INFO("%s %s timeout", hostname, port)
	except IOError as e:
		INFO('%s', e)
	
	return data.strip()
	
def httpServ(dstIp, dstPort=80):
	serv = ''
	try:
		if dstPort in cfg.HTTP_PORTS: proto = 'http'
		if dstPort in cfg.HTTPS_PORTS: proto = 'https'
		res = requests.get(proto + '://' + dstIp + ":" + str(dstPort), timeout=2)
		INFO('Status code: %r', res.status_code)
		if 'server' in res.headers:
			serv = http_vers(res.headers['server'])
		res.close()
		if not serv and 400 <= res.status_code < 500:
			html = res.content
			soup = BeautifulSoup(html, "lxml")
			DEBUG('soup.address: %r', soup.address)
			if soup.address:
				serv = http_vers(soup.address)
		if not serv:
			serv = ('[HTTP GET status {}]'.format(res.status_code),)
	except requests.Timeout:
		INFO("%s %s timeout", dstIp, dstPort)
	except IOError as e:
		INFO('%s', e) 
		
	return serv
	
def http_vers(serviceString):
	list_http = ['Apache','Apache Tomcat','busybox httpd','Microsoft-IIS','lighttpd','nginx','Sun-Java-System-Web-Server','Zeus']
	for server in list_http:
		if re.search(server, serviceString, re.I):
			version = re.search("/((?:\d+\.)+\d+)", serviceString).group(1)
			INFO("version: %r", version)
			return server, version
	return ()

def ftp_vers(serviceString):
	dict_ftp = {"FileZilla Server":"[0-9.]+[0-9.]+[0-9]* | [0-9.]+[0-9.]+[0-9a]","vsFTPd":"(.+ \d+\.\d+\.\d+)","ProFTPD":"[0-9.]+[0-9.]+[0-9.]+[0-9]rc","WeOnlyDo-wodFTPD":"[0-9.]+[0-9.]+[0-9]*"}
	for service, regex in dict_ftp.items():
		researchVer = re.search(regex, serviceString, re.I)
		if re.search(service, serviceString, re.I):
			if service == "WeOnlyDo-wodFTPD":
				service = "freeFTPd"
				
			if researchVer:
				version = researchVer.group(0)
				version = version.replace("(","").replace(")","")
				break
			return service, version
	return ()
				
def ssh_vers(serviceString):
	dict_ssh = {"OpenSSH":"_([0-9.]+[0-9.]+[0-9]+p+[0-9])","WeOnlyDo-wodSSHD":" ([0-9.]+[0-9.]+[0-9]*)"}
	for service,regex in dict_ssh.items():
		researchVer = re.search(regex,serviceString,re.I)
		if re.search(service,serviceString,re.I):
			if service == "WeOnlyDo-wodSSHD":
				service = "freeSSHd"
			
			if researchVer:
				version = researchVer.group(1)
				break
			return service, version
	return ()
		
def versionBindDns(dstIp, dstPort):
	res = sr1(IP(dst=dstIp)/UDP(dport=dstPort)/DNS(rd=1,qd=DNSQR(qclass=3, qtype=16, qname='version.bind.')))
	return res[DNS].an.rdata.strip()

def searchCVE(service, version):
	"""Return a list of strings"""
	re.search
	url = "https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword="+service+"+"+version
	res = requests.get(url)
	soup = BeautifulSoup(res.content, "lxml")
	
	listCVE = []
	for elt in soup.find_all('a', attrs={'href' : re.compile("^/cgi-bin/")}):
		listCVE.append(elt.get_text())
	return url, listCVE

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
		
	if os: INFO('OS: %r', os)
	
	return os
	
def toService(port, fingerprint='', fmt=True):
	if fingerprint != '':
		return fingerprint
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
