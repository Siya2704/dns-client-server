from library import *
sock = socket(AF_INET, SOCK_DGRAM)
sock.bind(('127.0.0.51',53))
sock2 = socket(AF_INET, SOCK_DGRAM)

def entry_cache(query, response, start, number_response):
	hostname,t,c,start = get_query_details(query)
	try:
		with open("cache.json", 'a') as fp:
			types = [1,2,5,6,15,16,28]
			if t in types:
				print("**Writing to cache(",hostname,")**")
			for i in range(number_response):
				type = response[start+3]
				clas = response[start+5]
				t1 = response[start+6]; t2 = response[start+7]
				t3 = response[start+8]; t4 = response[start+9]
				ttl = int(t1)*(16**6) + int(t2)*(16**4) + int(t3)*(16**2)+int(t4)
				toe = int(round(time.time()))
				length = response[start+11]
				#toe=time of entry
				if type in types:
					data = response[start:start+length+12]
					lst = []
					for k in data:
						lst.append(k)
					record = {"query":hostname,"type":t,"act_type":type,"class":clas,"ttl":ttl,"toe":toe,"data":lst}
					json.dump(record,fp)
					fp.write('\n')
					
				start += length + 12
	except Exception:
		print("**unable to write to cache**")

def lookup_cache(name, type, clas,query,start):
	x = query[:2] + bytes('\x81\x80','iso-8859-1')+query[4:7]
	y = bytes('','utf-8')
	count = 0
	flag = 0 #if entry found set to 1
	print("**Searching in cache(",name,")**")
	with open("cache.json", 'r') as fp:
		for line in fp.readlines():
			dct = json.loads(line)
			if(dct['query'] == name and dct['type'] == type and dct['class'] == clas and int(round(time.time()))< dct['toe']+dct['ttl']):
				if dct['act_type'] == type:
					flag = 1
				count += 1
				lst = dct["data"]
				for k in lst:
					y+= bytes(chr(k),'iso-8859-1')

	x += bytes(chr(count)+"\x00\x00" + "\x00\x00",'iso-8859-1')
	x+=query[12:start]
	x += y
	if(count == 0):
		return 0,flag
	return x,flag
	
def update_cache():
	items_to_keep = []
	with open("cache.json", 'r') as fp:
		for line in fp.readlines():
			dct = json.loads(line)
			if(int(round(time.time()))< dct['toe']+dct['ttl']):
				items_to_keep.append(dct)
	with open("cache.json", 'w') as fp:
		for item in items_to_keep:
			json.dump(item,fp)
			fp.write('\n')
	
def dns_response(ip,query):
	list = []# to contain servers ip from root
	sock2.settimeout(6)
	sock2.sendto(query, (ip, 53))
	response, addr2 = sock2.recvfrom(2048)
	number_queries, number_response, number_authority, number_additional, rcode= data_packet_dns(response)
	a_dc,b_dc,c_dc,start = get_query_details(query)
	if(number_response):
		entry_cache(query, response, len(query), number_response)
		return response,addr2,True
	#start of authoritative answer	
	for i in range(number_authority):
		length = start + 10
		a = response[length]
		b = response[length+1]
		length = int(a)*16*16 + int(b)
		start += length + 12
	#now start points to additional records
	for i in range(number_additional):
		if(response[start+3] == 1):#type A response
			name, ip = get_ipv4(response,start)
			list.append((name,ip))
		lent = response[start+11]
		start += lent + 12
			
	return list, addr2, False	

def iterate_query(root,query):#for iterative query
	for r in root:
		print("sending query to ", r[0], r[1])
		res, addr, got = dns_response(r[1],query)
		if (got == True):#found
			return res
		if len(res) == 0:
			continue
		else:
			return iterate_query(res, query)
	return -1

def main_server(query,addr):
	#look cache
	try:
		x,flag =0,0
		name,typ,clas,start = get_query_details(query)
		x,flag = lookup_cache(name, typ, clas,query,start)
		if(x != 0 and flag!=0):
			print("\nResponse sent from cache(",name,") \n")
			sock.sendto(x,addr)
			return
	except:
		pass
	tuple_data_dns = struct.unpack('!HHHHHH', query[:12])
	flags = tuple_data_dns[1] 
	rd = (flags & 256) != 0
	if(rd == 1):
		#recursive
		print("***Recursive Query***")
		dns = "8.8.8.8"
		sock2.sendto(query, (dns, 53))
		response, addr2 = sock2.recvfrom(2048)
		tuple_data_dns = struct.unpack('!HHHHHH', response[:12])
		number_response = tuple_data_dns[3]
		if number_response >0:
			entry_cache(query, response, start, number_response)
		print("\nResponse sent (",name,"): \n")
		sock.sendto(response,addr)
	else:
		#iterative
		print("***Iterative Query***")
		root = [("l.root-servers.net",'199.7.83.42')]#ICANN
		got = False
		try:
			response = iterate_query(root, query)
		except Exception:#timeout
			response = -1
		if(response == -1):
			print("Cannot resolve");
			sock.sendto("-1".encode(),addr)
		else:
			print("\nResponse sent (",name,"): \n")
			sock.sendto(response,addr)


def main():
	fp = open('cache.json','a')
	fp.close()
	while True:
		#continuously updating cache
		th = Thread(target = update_cache)
		th.start()
		query, addr = sock.recvfrom(2048)
		print("\nQuery received: ",query,"\n")
		th2 = Thread(target = main_server, args = (query,addr,))
		th2.start()
		
if __name__ == "__main__":
	main()
