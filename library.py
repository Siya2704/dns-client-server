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
    return queries, response, authority, additional, rcode, data[12:]
    
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
	
def get_ipv4(response,start):
	if(response[start+3] == 1):#type A response
		start += 12 #points to start of ip address
		ip = response[start:start+4]
		ipv4 = ""
		for j in range(0,4):
			ipv4 += str(ip[j])
			if(j != 3):
				ipv4 += "."
		return ipv4

def get_ipv6(reply,start):
	beg = start+12
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
	return ipv6	
		

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
