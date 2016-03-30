#!/usr/bin/env python
# -*- coding: Utf-8 -*-

import ScanPie

import networkx as nx
from networkx.readwrite import d3_js
import matplotlib.pyplot as plt # Otherwise draw doesn't work

COLORS_ETAT = {'open': '#00FF00', 'closed': '#FF0000', 'filtered': '#AA00AA', 'nores': '#AAAAAA'}

def toGraph(results):
	graph = nx.Graph()
	colors = []

	ownIp = ScanPie.ifaceAddress(ScanPie.conf.iface)
	graph.add_node(ownIp, color='#FFFFFF')
	for ip, ipRes in results.iteritems():
		graph.add_node(ip, color='#FFFFFF')
		graph.add_edge(ownIp, ip)
		for port, portRes in ipRes.iteritems():
			graph.add_node(port, color=COLORS_ETAT[portRes['etat']])
			#if portRes['etat'] == 'open':
			graph.add_edge(ip, port)
			#graph[ip][port]['color'] = COLORS_ETAT[portRes['etat']]
	
	print graph
	return graph

def drawAndExport(graph):
	nx.draw(graph, node_color=[graph.node[node]['color'] for node in graph])   # default spring_layout
	plt.show()
	#plt.savefig("graph.png")
	d3_js.export_d3_js(graph, files_dir="viz", graphname="test", node_labels=True, group=None)

if __name__ == '__main__':
	res = ScanPie.ScanResults([('192.168.56.101', {512: {'etat': 'open', 'cve': '', 'service': ''}, 1: {'etat': 'closed'}, 514: {'etat': 'open', 'cve': '', 'service': ''}, 515: {'etat': 'closed'}, 8433: {'etat': 'closed'}, 513: {'etat': 'open', 'cve': '', 'service': ''}, 5000: {'etat': 'closed'}, 137: {'etat': 'closed'}, 139: {'etat': 'open', 'cve': '', 'service': ''}, 143: {'etat': 'closed'}, 8080: {'etat': 'closed'}, 8081: {'etat': 'closed'}, 1027: {'etat': 'closed'}, 20: {'etat': 'closed'}, 21: {'etat': 'open', 'cve': '', 'service': '220 (vsFTPd 2.3.4)'}, 22: {'etat': 'open', 'cve': '', 'service': 'SSH-2.0-OpenSSH_4.7p1 Debian-8ubuntu1'}, 23: {'etat': 'open', 'cve': '', 'service': ''}, 25: {'etat': 'open', 'cve': '', 'service': ''}, 1434: {'etat': 'closed'}, 1433: {'etat': 'closed'}, 548: {'etat': 'closed'}, 1723: {'etat': 'closed'}, 6001: {'etat': 'closed'}, 135: {'etat': 'closed'}, 32768: {'etat': 'closed'}, 2483: {'etat': 'closed'}, 2484: {'etat': 'closed'}, 53: {'etat': 'open', 'cve': u'https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=Bind+9.4.2 CVE-2008-0122', 'service': 'Bind/9.4.2'}, 3128: {'etat': 'closed'}, 443: {'etat': 'closed'}, 445: {'etat': 'open', 'cve': '', 'service': ''}, 5432: {'etat': 'open', 'cve': '', 'service': ''}, 8000: {'etat': 'closed'}, 1025: {'etat': 'closed'}, 199: {'etat': 'closed'}, 8008: {'etat': 'closed'}, 8009: {'etat': 'open', 'cve': '', 'service': ''}, 587: {'etat': 'closed'}, 80: {'etat': 'open', 'cve': '', 'service': ''}, 81: {'etat': 'closed'}, 32769: {'etat': 'closed'}, 2525: {'etat': 'closed'}, 990: {'etat': 'closed'}, 8888: {'etat': 'closed'}, 993: {'etat': 'closed'}, 995: {'etat': 'closed'}, 2049: {'etat': 'open', 'cve': '', 'service': ''}, 465: {'etat': 'closed'}, 873: {'etat': 'closed'}, 3050: {'etat': 'closed'}, 1900: {'etat': 'closed'}, 5357: {'etat': 'closed'}, 110: {'etat': 'closed'}, 111: {'etat': 'open', 'cve': '', 'service': ''}, 6000: {'etat': 'open', 'cve': '', 'service': ''}, 1521: {'etat': 'closed'}, 6002: {'etat': 'closed'}, 631: {'etat': 'closed'}, 1528: {'etat': 'closed'}, 3306: {'etat': 'open', 'cve': '', 'service': ''}})])
	res.setOS('192.168.56.101', 'Linux')
	G = toGraph(res)
	#G = nx.cubical_graph()

	drawAndExport(G)
	
