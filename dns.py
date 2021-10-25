import sys
import struct
from socket import*
import os.path
from threading import Thread
import time
import ctypes # to create buffers
import codecs
#public DNS server for Google DNS.
server = '8.8.8.8'
#DNS server runs on port 53
serverPort = 53 

def constructQuery(hostname, _type, _class):
	query = bytes("\x08\x08" + "\x00\x00" + "\x00\x01" + "\x00\x00" + "\x00\x00" + "\x00\x00", 'utf-8')
	d = bytes("", 'utf-8')

	for a in hostname.split('.'):
		d += struct.pack("!b" + str(len(a)) + "s", len(a), bytes(a, "utf-8"))

	query = query +  d +  bytes("\x00", 'utf-8') #terminate domain with zero len
	if _type=='A'and  _class=="IN":
		query = query + bytes("\x00\x01" + "\x00\x01", 'utf-8') #type A, class IN
	elif _type=='AAAA'and  _class=="IN":
		query = query + bytes("\x00\x1c" + "\x00\x01", 'utf-8') #type AAAA, class IN
	elif _type=='NS'and  _class=="IN":
		query = query + bytes("\x00\x02" + "\x00\x01", 'utf-8') #type NS, class IN
	elif _type=='MX'and  _class=="IN":
		query = query + bytes("\x00\x0f" + "\x00\x01", 'utf-8') #type MX, class IN
	elif _type=='CNAME'and  _class=="IN":
		query = query + bytes("\x00\x05" + "\x00\x01", 'utf-8') #type CNAME, class IN
	#print('query is', query)
	return query

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
    return number_queries, number_response, rcode, data[12:]
    
def getip(query,_type,hostname):
	rcode=1
	retry=0
	sock = socket(AF_INET, SOCK_DGRAM)
	while rcode != 0 and retry < 10:
		sock.sendto(query, (server, serverPort))
		reply, addr = sock.recvfrom(2048)
		number_queries, number_response, rcode, reply = data_packet_dns(reply)
		retry += 1
	if rcode != 0:
		print("** server can't find", hostname,":No answer")
		return 0;
	#if rcode is zero then ok
	start = 0
	while True:
		try:
			if reply[start] == 192 and reply[start+1] == 12:
				break;
			else:
				start += 1
		except:
			return 0
	if _type=='A':
		y = 0
		for i in range(0,number_response):
			beg = start+y+12
			#last 4 bytes contains ip address
			ip = reply[beg:beg+4]
			#ip address in bytes
			#convert byte to string
			ipv4 = ""
			for i in range(0,4):
				ipv4 += str(ip[i])
				if(i != 3):
					ipv4 += "."
			#ipv4 has ip address
			ip = ipv4
			print("Name:\t",hostname)
			print("Address: ",ip)
			y+=16
		
	elif _type=="AAAA":
		y = 0
		for i in range(0,number_response):
			beg = start+y+12
			#last 16 bytes contains ip address
			ip = reply[beg:beg+16]
			#ip address in bytes
			#convert byte to string
			ipv6 = ""
			for i in range(0,16,2):
				a = str(hex(ip[i])).split('0x',1)[1]
				b = str(hex(ip[i+1])).split('0x',1)[1]
				if(len(b) < 2):
					b = "0"+ b
				ipv6 += a+b
				if(i != 14):
					ipv6 += ":"
			#ipv6 has ip address
			ip = ipv6
			print("Name:\t",hostname)
			print("Address: ",ip)
			y+=28

def type_NS(query,_type,hostname):
	rcode=1
	retry=0
	sock = socket(AF_INET, SOCK_DGRAM)
	while rcode != 0 and retry < 10:
		sock.sendto(query, (server, serverPort))
		reply, addr = sock.recvfrom(2048)
		number_queries, number_response, rcode, reply = data_packet_dns(reply)
		retry += 1
	if rcode != 0:
		print("** server can't find", hostname,":No answer")
		return 0
	start = 0
	while True:
		#\xc0\x0c
		try:
			if reply[start] == 192 and reply[start+1] == 12:
				break;
			else:
				start += 1
		except:
			return 0	
	y = 0
	k = reply[start+y+11] #length
	beg = start+y+12
	a = reply[beg+k-1]
	b = reply[beg+k-2]
	for i in range(0,number_response):
		beg = start+y+12
		length = reply[start+y+11]
		res =""
		for i in range (beg+1,beg+length-2):
			x = reply[i]
			if (x==0 or x==1 or x==2 or x==3 or x==4 or x==5 or x==6 or x==7 or x==8 or x==9 or x==10 or x==11 or x==12 or x==13 or x==14 or x==15):
				res += "."
			else:
				res += chr(reply[i])
		if length < k:
			pointer = reply[beg+length-1] - 12
			end = k - length
			for i in range (pointer,pointer+end):
				x = reply[i]
				if (x==0 or x==1 or x==2 or x==3 or x==4 or x==5 or x==6 or x==7 or x==8 or x==9 or x==10 or x==11 or x==12 or x==13 or x==14 or x==15):
					res += "."
				else:
					res += chr(reply[i])
			 
		if a == 12 and b == 192: #ie 0c
			print(hostname,"\tnameserver = ",res+"."+hostname+".")
		else:
			print(hostname,"\tnameserver = ",res+".")
		y+=12+length
         
def type_MX(query,_type,hostname):
	rcode=1
	retry=0
	sock = socket(AF_INET, SOCK_DGRAM)
	while rcode != 0 and retry < 10:
		sock.sendto(query, (server, serverPort))
		reply, addr = sock.recvfrom(2048)
		number_queries, number_response, rcode, reply = data_packet_dns(reply)
		retry += 1
	if rcode != 0:
		print("** server can't find", hostname,":No answer")
		return 0
	start = 0
	while True:
		try:
			if reply[start] == 192 and reply[start+1] == 12:
				break;
			else:
				start += 1
		except:
			return 0
	
	y = 0
	k = reply[start+y+11] - 2 #length (excluding preference)
	beg = start+y+14
	a1 = reply[beg+k-1]
	b1 = reply[beg+k-2]
	for i in range(0,number_response):
		beg = start+y+14
		a = reply[beg-2]
		b = reply[beg-1]
		preference = int(a)*16*16 + int(b)
		length = reply[start+y+11] - 2
		res = str(preference)+" "
		if length < k:
			temp = beg+length-2 #to remove c0
		else:
			temp = beg+length-1
		for i in range (beg+1,temp):
			x = reply[i]
			if (x==0 or x==1 or x==2 or x==3 or x==4 or x==5 or x==6 or x==7 or x==8 or x==9 or x==10 or x==11 or x==12 or x==13 or x==14 or x==15):
				res += "."
			else:
				res += chr(reply[i])
		if length < k:
			pointer = reply[beg+length-1] -12
			end = k - length
			for i in range (pointer,pointer+end+1):
				x = reply[i]
				if (x==0 or x==1 or x==2 or x==3 or x==4 or x==5 or x==6 or x==7 or x==8 or x==9 or x==10 or x==11 or x==12 or x==13 or x==14 or x==15):
					res += "."
				else:
					res += chr(reply[i])
					
		if a1 == 12 and b1 == 192: #ie 0c
			print(hostname,"\tmail exchanger = ",res+"."+hostname+".")
		else:
			print(hostname,"\tmail exchanger = ",res+".")
		y+=14+length


def type_CNAME(query,_type,hostname):
	rcode=1
	retry=0
	sock = socket(AF_INET, SOCK_DGRAM)
	while rcode != 0 and retry < 10:
		sock.sendto(query, (server, serverPort))
		reply, addr = sock.recvfrom(2048)
		number_queries, number_response, rcode, reply = data_packet_dns(reply)
		retry += 1
	if rcode != 0:
		print("** server can't find", hostname,":No answer")
		return 0
	start = 0
	while True:
		#\xc0\x0c
		try:
			if reply[start] == 192 and reply[start+1] == 12:
				break;
			else:
				start += 1
		except:
			return 0
	y = 0
	beg = start+12
	for i in range(0,number_response):
		length = reply[start+11+y]
		res =""
		for i in range (beg+y+1,beg+y+length-1):
			x = reply[i]
			if x == 192:#next is pointer
				pointer = reply[i+1] - 12
				for j in range (pointer,pointer+length):
					k = reply[j]
					if k == 0:
						break;
					if (k==1 or k==2 or k==3 or k==4 or k==5 or k==6 or k==7 or k==8 or k==9 or k==10 or k==11 or k==12 or k==13 or k==14 or k==15):
						res += "."
					else:
						res += chr(reply[j])
						
			elif (x==0 or x==1 or x==2 or x==3 or x==4 or x==5 or x==6 or x==7 or x==8 or x==9 or x==10 or x==11 or x==12 or x==13 or x==14 or x==15):
				res += "."
			else:
				res += chr(reply[i])
		print(hostname,"\tcanonical name = "+res+"")
		y+=12+length	
	
	
def finalCall(hostname,type):
	print("Server:		8.8.8.8")#127.0.0.53
	print("Address:	8.8.8.8#53")
	print("\nNon-authoritative answer:")
	
	query = constructQuery(hostname,type,"IN")
	if type =='A':
		ip= getip(query,'A',hostname)
	if type =='AAAA':
		ip= getip(query,"AAAA",hostname)
	if type =='NS':
		ip= type_NS(query,"NS",hostname)
	if type =='MX':	
		type_MX(query,"MX",hostname)
	if type =='CNAME':	
		type_CNAME(query,"CNAME",hostname)
			
			
def main():
	hostname = sys.argv[1]
	try:
		type=sys.argv[2]
		type = type.split('-type=',1)[1]
		finalCall(hostname,type)
	except:
		finalCall(hostname,'A')

if __name__ == "__main__":
	main()


