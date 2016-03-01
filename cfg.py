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
