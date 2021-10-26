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
	start = len(query) - 12#start of authoritative answer
	x = 0
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
	return list

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
	ip = '199.7.83.42'#ICANN server
	#ip = '37.209.192.12'
	list = ['37.209.192.12', '37.209.194.12', '37.209.196.12', '37.209.198.12', '156.154.100.20', '156.154.101.20']
	query, addr = sock.recvfrom(2048)
	root = dns_response(ip,query)
	print(root)
	#hostname = get_hostname(query)
	#hostname2 = hostname.split('.',1)[0] #removing .in or .com
	#type = query[len(query)-2]
	#clas = query[len(query)-1]
	#query = constructQuery(hostname2,type,clas)
	for ip in root:
		tld_temp = dns_response(ip,query)
		print("name = ", tld_temp)
		#tld.append(tld_tmp)



