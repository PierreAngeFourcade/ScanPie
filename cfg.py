#!/usr/bin/env python
# -*- coding: Utf-8 -*-


from time import time, strftime
import logging

logging.basicConfig(level=logging.DEBUG, format='%(message)s')
logger = logging.getLogger(__name__)
#logger.addHandler(logging.NullHandler())

VERBOSE = 0
DEBUG = 1

def timestamp():
	return '%s.%s' % (strftime('%H:%M:%S'), str(time()).split('.')[1][:2])
	
def DEBUG(msg, *args):
	if DEBUG:
		logger.debug(msg, *args)
	
def STATUS(msg, *args): 
	if VERBOSE == 2:
		logger.info(timestamp() + " " + msg, *args)
		
def PEDANTIC(msg, *args): 
	if VERBOSE == 2:
		logger.info(msg, *args)
	
def INFO(msg, *args): 
	if VERBOSE == 1:
		logger.info(msg, *args)
		
def WARN(msg, *args): 
	if VERBOSE == 1:
		logger.warning(msg, *args)

		
def ERROR(msg, *args):
	logger.error(msg, *args)

def PRINT(msg, *args):
	logger.error(msg, *args)

# Server ports
# 1-1023: well-known, 1024-49151: vendor registered, 49152-65535: dynamic/private
VERY_COMMON_PORTS = [20, 21, 22, 23, 53, 80, 443, 1027, 8000, 8080] # FTP, SSH, Telnet, DNS, HTTP, HTTPS, IIS, HTTP Proxy, HTTP-alt
OTHER_COMMON_PORTS = [81, 990, 3128, 8008, 8009, 8081, 8433, 8888, 32768, 32769] # HOSTS2, FTPS, Squid proxy, IBM HTTP, Apache JServ, various HTTP, Sun HTTP, HTTPS-alt, IBM Filenet
DATABASE_PORTS = [1433, 1434, 1521, 1528, 2483, 2484, 3050, 3306, 5432] # MySQL, PostgreSQL, MSSQL, Oracle
EMAIL_PORTS = [25, 110, 143, 465, 587, 993, 995, 2525] # SMTP, POP3, IMAP, SMTPS, SMTP-alt, IMAPS, POPS, SMTP-alt
SHARED_SERVICE_PORTS = [111, 135, 137, 139, 445, 515, 548, 631, 873, 1025, 2049, 5357] # RPC bind, MSRPC, SMB, UNIX Printing, AFP/IP, CUPS, rsync, NFS or IIS, NFS, WSD-api
OTHER_COMMON2_PORTS = [1, 199, 512, 513, 514, 1723, 1900, 5000, 6000, 6001, 6002] # tcpmux, SNMP mux, exec, login, shell, PPTP, UPNP, X11
AUTH_PORTS = [88, 389, 464, 543, 544, 636, 2105, 3268, 3269] # Kerberos, LDAP
REMOTE_ADMIN_PORTS = [625, 3389, 5631, 5800, 5900] # Apple Xserver admin, MS RDP, pcanywhere-data, VNC HTTP, VNC
ROUTING_PORTS = [161, 162, 179, 1993, 1998, 2000] # SNMP, BGP, Cisco SNMP TCP, Cisco X.25 service, Cisco SCCP
VOIP_PORTS = [5060, 5061] # SIP, SIP-TLS
HTTP_PORTS = [80, 8080, 8008, 8009, 8081, 8888]
HTTPS_PORTS = [443, 8443]
COMMON_PORTS = VERY_COMMON_PORTS + OTHER_COMMON_PORTS + OTHER_COMMON2_PORTS + SHARED_SERVICE_PORTS + EMAIL_PORTS + DATABASE_PORTS
ALL_COMMON_PORTS = COMMON_PORTS + AUTH_PORTS + OTHER_COMMON2_PORTS + REMOTE_ADMIN_PORTS + ROUTING_PORTS + VOIP_PORTS
# Client ports
# 49152-65535 (Windows/BSD), 32768-61000 (Linux >= 2.4), 1024-4999 (Linux < 2.4)
