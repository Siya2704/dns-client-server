import sys, struct, os.path, time, json, ipaddress, random, codecs
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
	elif type=='SOA'and clas=="IN":
		query = query + bytes("\x00\x06" + "\x00\x01", 'utf-8') #type SOA, class IN
	elif type=='TXT'and clas=="IN":
		query = query + bytes("\x00\x10" + "\x00\x01", 'utf-8') #type TXT, class IN
	elif type=='PTR'and clas=="IN":
		query = query + bytes("\x00\x0c" + "\x00\x01", 'utf-8') #type PTR, class IN
	return query

def str_from_pointer(response, p):
	i = 0
	while(response[i]!=192 and response[i+1]!=12):#start of answer
		start = i+1
		i+=1
		
	res = ""
	i = 0
	if p < start:
		stop = len(response)-p
	else:
		length = response[p-1]
		stop = p+length-1
		
	while (p < stop):
		size = response[p]
		if(size == 192):
			res += str_from_pointer(response, response[p+1])
			p+=1
			res += "."
			continue
		if(size == 0):
			break
		for j in range(1,size+1):
			res += chr(response[p+j])
		res += "."
		p += size+1
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
	return res,ipv4

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
	return res,ipv6	
		
def get_NS(response,start):#also same for CNAME
	#nameserver
	res="";ns="";
	if(response[start] == 192):
		res += str_from_pointer(response, response[start+1])
	
	start = start+12
	ns = str_from_pointer(response, start)			
	return res[:-1],ns[:-1]

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
	return res[:-1],str(preference)+" "+mx[1:-1]

def get_TXT(response,start):#also same for CNAME
	res="";txt="";
	if(response[start] == 192):
		res += str_from_pointer(response, response[start+1])
					
	start = start+12
	txt = str_from_pointer(response, start)	
	return res[:-1],txt[:-1]

def get_time(response,start):
	t1 = response[start]; t2 = response[start+1]
	t3 = response[start+2]; t4 = response[start+3]
	ttl = int(t1)*(16**6) + int(t2)*(16**4) + int(t3)*(16**2)+int(t4)
	return ttl

def get_SOA(response,start):
	res="";
	if(response[start] == 192):
		res += str_from_pointer(response, response[start+1])
					
	length = response[start+11]		
	start = start+12
	pns = "" #primary name server
	ram = "" #responsible authority's mailbox
	mt = get_time(response,start+length-4)#minimum ttl
	el = get_time(response,start+length-8)#expire limit
	rti = get_time(response,start+length-12)#retry interval
	rfi = get_time(response,start+length-16)#refresh interval
	sn = get_time(response,start+length-20)#serial number
	for i in range(start,start+length-20):
		x = response[i]
		if x == 192:
			pns += "."+str_from_pointer(response, response[i+1])
			i+=2
			break
		elif x in range(0, 16):
			pns += "."
		else:
			pns += chr(response[i])

	for j in range(i,start+length-20):
		x = response[j]
		if x == 192:
			ram += "."+str_from_pointer(response, response[j+1])
			break
		elif x in range(0, 16):
			ram += "."
		else:
			ram += chr(response[j])
	return res[:-1],pns[1:-1],ram[1:-1],sn,rfi,rti,el,mt

def get_PTR(response,start):
	addr="";name="";
	if(response[start] == 192):
		addr += str_from_pointer(response, response[start+1])
					
	length = response[start+11]		
	start = start+12
	for i in range(start,start+length):
		x = response[i]
		if x == 192:
			name += str_from_pointer(response, response[i+1])
			i+=1
		elif x in range(0, 16):
			name += "."
		else:
			name += chr(response[i])
	return addr[1:],name[1:]

def get_query_details(query):
	length = len(query)
	start = 12
	st = ""
	while start < length:
		size = query[start]
		if(size == 0):
			break
		for j in range(1,size+1):
			st += chr(query[start+j])
		st += "."
		start += size+1
	type = query[start+2]
	clas = query[start+4]
	start += 5
	return st[:len(st) - 1] ,type, clas, start
