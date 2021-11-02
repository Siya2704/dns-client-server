import sys
import struct
from socket import*
import os.path
from threading import Thread
import time
import ctypes # to create buffers
import codecs

# source = https://stackoverflow.com/questions/54278329/how-to-parse-dns-question-field-with-python-raw-sockets
def data_packet_dns(data):
    tuple_data_dns = struct.unpack('!HHHHHH', data[:12])
    identification = tuple_data_dns[0]
    flags = tuple_data_dns[1] 
    number_queries = tuple_data_dns[2]
    number_response = tuple_data_dns[3]
    number_authority = tuple_data_dns[4]
    number_additional = tuple_data_dns[5]
    qr = (flags & 32768) != 0
    opcode = (flags & 30720 ) >> 11
    aa = (flags & 1024) != 0
    tc = (flags & 512) != 0
    rd = (flags & 256) != 0
    ra = (flags & 128) != 0
    z = (flags & 112) >> 4
    rcode = flags & 15
    return number_queries, number_response, number_authority, number_additional, rcode, data[12:]
    
def constructQuery(hostname, type, clas,recurse):#1 means recursion desired
	if(recurse == 1):
		query = bytes("\x08\x08" + "\x01\x00" + "\x00\x01" + "\x00\x00" + "\x00\x00" + "\x00\x00", 'utf-8')
	else:
		query = bytes("\x08\x08" + "\x00\x00" + "\x00\x01" + "\x00\x00" + "\x00\x00" + "\x00\x00", 'utf-8')
	d = bytes("", 'utf-8')

	for a in hostname.split('.'):
		d += struct.pack("!b" + str(len(a)) + "s", len(a), bytes(a, "utf-8"))

	query = query +  d +  bytes("\x00", 'utf-8') #terminate domain with zero len
	if type=='A'and clas=="IN":
		query = query + bytes("\x00\x01" + "\x00\x01", 'utf-8') #type A, class IN
	elif type=='AAAA'and clas=="IN":
		query = query + bytes("\x00\x1c" + "\x00\x01", 'utf-8') #type AAAA, class IN
	elif type=='NS'and clas=="IN":
		query = query + bytes("\x00\x02" + "\x00\x01", 'utf-8') #type NS, class IN
	elif type=='MX'and clas=="IN":
		query = query + bytes("\x00\x0f" + "\x00\x01", 'utf-8') #type MX, class IN
	elif type=='CNAME'and clas=="IN":
		query = query + bytes("\x00\x05" + "\x00\x01", 'utf-8') #type CNAME, class IN
	#print('query is', query)
	return query
	
def get_ipv4(response,start,number_response):
	ip_addr =[]
	for i in range(number_response):
		if(response[start+3] == 1):#type A response
			start += 12 #points to start of ip address
			ip = response[start:start+4]
			ipv4 = ""
			for j in range(0,4):
				ipv4 += str(ip[j])
				if(j != 3):
					ipv4 += "."
			ip_addr.append(ipv4);
			start += 4;
		else:
			lent = response[start+11]
			start += lent + 12
	return ip_addr, start
	
def get_hostname(query):
	length = len(query) - 16
	query = query[12: 12+length]
	st = ""
	i = 0
	while i < length:
		size = query[i]
		for j in range(1,size+1):
			st += chr(query[i+j])
		st += "."
		i += size+1
	st = st[:len(st) - 2] #removing last two .
	return st
