from library import *
sock = socket(AF_INET, SOCK_DGRAM)
sock.bind(('127.0.0.1',53))
sock2 = socket(AF_INET, SOCK_DGRAM)

def dns_response(ip,query):
	list = []# to contain servers ip from root
	sock2.sendto(query, (ip, 53))
	response, addr2 = sock2.recvfrom(2048)
	number_queries, number_response, number_authority, number_additional, rcode, response = data_packet_dns(response)
	#building response
	start = len(query) - 12#start of answer
	y = 12
	ip_addr =[]
	for i in range(number_response):
		beg = start+y
		ip = response[beg:beg+4]
		ipv4 = ""
		for i in range(0,4):
			ipv4 += str(ip[i])
			if(i != 3):
				ipv4 += "."
		ip_addr.append(ipv4)
		y+=16
		start += 16#start of authoritative answer	
	x = 0
	if(number_response):
		return ip_addr,True
		
	for i in range(number_authority):
		length = start + 10
		a = response[length]
		b = response[length+1]
		length = int(a)*16*16 + int(b)
		start += length + 12
	#now start points to additional records
	for i in range(number_additional):
		if(response[start+3] == 1):#type A response
			start += 12 #points to start of ip address
			ip = response[start:start+4]
			ipv4 = ""
			for j in range(0,4):
				ipv4 += str(ip[j])
				if(j != 3):
					ipv4 += "."
			list.append(ipv4);
			start += 4;
		else:
			lent = response[start+11]
			start += lent + 12
			
	return list, False	

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

while True:
	root = ['199.7.83.42']#ICANN server
	query, addr = sock.recvfrom(2048)
	hostname = get_hostname(query)
	query_to_send = constructQuery(hostname,'A',"IN")
	got = False
	while True:
		if (got == True):#found
			print("found")
			break
		else:
			print("sending query to ", root[0])
			store_root = root
			root, got = dns_response(root[0],query_to_send)
		
	ip = store_root[0]
	sock2.sendto(query, (ip, 53))
	response, addr2 = sock2.recvfrom(2048)
	sock.sendto(response,addr)



