import sys, struct, os.path, time, json
from socket import*
from threading import Thread

# source = https://stackoverflow.com/questions/54278329/how-to-parse-dns-question-field-with-python-raw-sockets
def data_packet_dns(data):
    tuple_data_dns = struct.unpack('!HHHHHH', data[:12])
    identification = tuple_data_dns[0]
    flags = tuple_data_dns[1] 
    queries = tuple_data_dns[2]
    response = tuple_data_dns[3]
    authority = tuple_data_dns[4]
    additional = tuple_data_dns[5]
    qr = (flags & 32768) != 0
    opcode = (flags & 30720 ) >> 11
    aa = (flags & 1024) != 0
    tc = (flags & 512) != 0
    rd = (flags & 256) != 0
    ra = (flags & 128) != 0
    z = (flags & 112) >> 4
    rcode = flags & 15
    return queries, response, authority, additional, rcode
    
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
	
def str_from_pointer(response, p):
	i = 0
	while(response[i]!=192 and response[i+1]!=12):#start of answer
		start = i+1
		i+=1
		
	res = ""
	if p < start:
		for i in range(p,len(response)-p):
			x = response[i]
			if x == 192:
				res += str_from_pointer(response, response[i+1])
				i+=1
			elif x == 0:
				#print("a  ",response[p:i])
				break
			elif x in range(1, 16):
				res += "."
			else:
				res += chr(response[i])
	else:
		length = response[start+11]
		#print("b  ",response[p:p+length])
		for i in range (p,start+12+length):
			x = response[i]
			if x == 192:
				res += str_from_pointer(response, response[i+1])
				i+=1
			elif x in range(0, 16):
				res += "."
			else:
				res += chr(response[i])
	return res

def get_ipv4(response,start):
	#name
	res = ""
	if(response[start] == 192):
		res += str_from_pointer(response, response[start+1])

	start += 12 #points to start of ip address
	ip = response[start:start+4]
	ipv4 = ""
	for j in range(0,4):
		ipv4 += str(ip[j])
		if(j != 3):
			ipv4 += "."
	return res[1:],ipv4

def get_ipv6(response,start):
	#name
	res = ""
	if(response[start] == 192):
		res += str_from_pointer(response, response[start+1])
					
	beg = start+12
	#last 16 bytes contains ip address
	ip = response[beg:beg+16]
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
	return res[1:],ipv6	
		
def get_NS(response,start):
	#nameserver
	res="";ns="";
	if(response[start] == 192):
		res += str_from_pointer(response, response[start+1])
					
	length = response[start+11]		
	start = start+12
	for i in range(start+1,start+length):
		x = response[i]
		if x == 192:
			ns += str_from_pointer(response, response[i+1])
			i+=1
		elif x in range(0, 16):
			ns += "."
		else:
			ns += chr(response[i])
	return res[1:],ns

def get_MX(response,start):
	#nameserver
	res="";mx="";
	if(response[start] == 192):
		res += str_from_pointer(response, response[start+1])
					
	length = response[start+11]
	a = response[start+12]
	b = response[start+13]
	preference = int(a)*16*16 + int(b)
	start = start+14
	for i in range(start,start+length-2):
		x = response[i]
		if x == 192:
			mx += str_from_pointer(response, response[i+1])
			i+=1
		elif x in range(0, 16):
			mx += "."
		else:
			mx += chr(response[i])
	return res[1:],str(preference)+" "+mx[1:]		

def get_query_details(query):
	clas = query[len(query) - 1]
	type = query[len(query) - 3]
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
	return st,type, clas
