#!/usr/bin/env python
# -*- coding: latin-1 -*-

import urllib  
import socket
import bs4 as BeautifulSoup
import re

def htmlDownload(url) :                                     
	sock = urllib.urlopen(url) 
	htmlSource = sock.read()                            
	sock.close()                                        
	return htmlSource

if __name__ == "__main__":
	listCVE = []
	test=htmlDownload("https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=apache+2.2.4") 
	soup = BeautifulSoup.BeautifulSoup(test, "lxml")
	for el in soup.find_all('a', attrs={'href' : re.compile("^/cgi-bin/")}):
		elt=el.get_text()
        	listCVE.extend(str(elt))
		listCVE.extend(" ")
		jointure="".join(listCVE)
	separateur=jointure.split(" ")
	taille = len(separateur)
	del separateur[taille-1]
	print separateur
