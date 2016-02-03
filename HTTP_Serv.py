#!/usr/bin/env python
# -*- coding: Utf-8 -*-

import requests
import bs4 as BeautifulSoup
import socket
import urllib

def test():
	dstIp="192.168.56.102"
	
	res = requests.head('http://' + dstIp + ":80", timeout=1)
	url = 'http://' + dstIp + ":80"
	sock = urllib.urlopen(url) 
	htmlSource = sock.read()                            
	sock.close()                                        
	soup = BeautifulSoup.BeautifulSoup(htmlSource, "lxml")

	if res.status_code == 200:
		serv = res.headers["server"]
		print serv
		#sep1=serv.split(' ')
		#sep2=sep1[0].split('/')
		
	elif res.status_code == 403 or 404:
		serv = '[HTTP status {}]'.format(res.status_code)
		print soup.address
	#return sep2[0],sep2[1]

if __name__=="__main__":
	test()
	#serv,ver=test()
	#print "serveur = "+serv
	#print "version = "+ver
