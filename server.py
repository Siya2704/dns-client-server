from library import *
sock = socket(AF_INET, SOCK_DGRAM)
sock.bind(('127.0.0.1',53))
sock2 = socket(AF_INET, SOCK_DGRAM)

def entry_cache(query, response, start, number_response):
	hostname,t,c = get_query_details(query)
	try:
		print("...Writing to cache")
		with open("cache.json", 'a') as fp:
			#name,c,t = get_query_details(query)
			for i in range(number_response):
				type = response[start+3]
				clas = response[start+5]
				t1 = response[start+6]; t2 = response[start+7]
				t3 = response[start+8]; t4 = response[start+9]
				ttl = int(t1)*(16**6) + int(t2)*(16**4) + int(t3)*(16**2)+int(t4)
				toe = int(round(time.time()))
				length = response[start+11]
				#toe=time of entry
				if type == 1:#A
					name,data = get_ipv4(response,start)
					record = {"query":hostname,"name":name,"type":type,"class":clas,"ttl":ttl,"toe":toe,"data":data}
					json.dump(record,fp)
					fp.write('\n')
				elif type == 28:#AAAA
					name,data = get_ipv6(response,start)
					record = {"query":hostname,"name":name,"type":type,"class":clas,"ttl":ttl,"toe":toe,"data":data}
					json.dump(record,fp)
					fp.write('\n')
				elif type == 2:#NS
					name,data = get_NS(response,start)
					record = {"query":hostname,"name":name,"type":type,"class":clas,"ttl":ttl,"toe":toe,"data":data}
					json.dump(record,fp)
					fp.write('\n')	
				elif type == 5:#CNAME
					name,data = get_NS(response,start)
					record = {"query":hostname,"name":name,"type":type,"class":clas,"ttl":ttl,"toe":toe,"data":data}
					json.dump(record,fp)
					fp.write('\n')
				elif type == 6:#SOA
					name,pns,ram,sn,rfi,rti,el,mt = get_SOA(response,start)
					data = [pns,ram,sn,rfi,rti,el,mt]
					print(data)
					record = {"query":hostname,"name":name,"type":type,"class":clas,"ttl":ttl,"toe":toe,"data":data}
					json.dump(record,fp)
					fp.write('\n')
				elif type == 15:#MX
					name,data = get_MX(response,start)
					record = {"query":hostname,"name":name,"type":type,"class":clas,"ttl":ttl,"toe":toe,"data":data}
					json.dump(record,fp)
					fp.write('\n')
				elif type == 16:#TXT
					name,txt = get_TXT(response,start)
					record = {"query":hostname,"name":name,"type":type,"class":clas,"ttl":ttl,"toe":toe,"data":txt}
					json.dump(record,fp)
					fp.write('\n')	
					
				start += length + 12
	except:
		print("..unable to write to cache")

def lookup_cache(name, type, clas):
	list  = []
	print("Looking in cache")
	with open("cache.json", 'r') as fp:
		for line in fp.readlines():
			dct = json.loads(line)
			if(dct['query'] == name and dct['type'] == type and dct['class'] == clas and int(round(time.time()))< dct['toe']+dct['ttl']):
				list.append((dct["name"],dct["type"],dct["data"]))
	return list
	
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
	sock2.sendto(query, (ip, 53))
	response, addr2 = sock2.recvfrom(2048)
	number_queries, number_response, number_authority, number_additional, rcode= data_packet_dns(response)
	
	start = len(query) - 12	
	if(number_response):
		entry_cache(query, response, len(query), number_response)
		return response,addr2,True
	response = response[12:] #removing headers
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
			
	return list, addr2, False	

def iterate_query(root,query):#for iterative query
	for r in root:
		print("sending query to ", r)
		res, addr, got = dns_response(r,query)
		if (got == True):#found
			return res
		if len(res) == 0:
			continue
		else:
			return iterate_query(res, query)
	return -1

def open_resolv():
	try:
		resolvconf = open(os.path.abspath("/etc/resolv.conf"),'r')
		for line in resolvconf.readlines():
			if '#' in line:
				pass
			elif 'nameserver' in line:
				resolver = line.split('nameserver ',1)[1]
				resolver = resolver.split('\n',1)[0]
				resolvconf.close()
				return resolver
	except Exception as e:
		print(e)
		resolvconf.close()
		exit()

def main():	
	#continuously updating cache
	th = Thread(target = update_cache)
	th.start()
	while True:
		query, addr = sock.recvfrom(2048)
		#look cache
		name,type,clas = get_query_details(query)
		x = lookup_cache(name, type, clas)
		if(len(x) != 0):
			lst = str(['found',x])
			sock.sendto(lst.encode(),addr)
			continue
		tuple_data_dns = struct.unpack('!HHHHHH', query[:12])
		flags = tuple_data_dns[1] 
		rd = (flags & 256) != 0
		if(rd == 1):
			#recursive
			print("***Recursive Query***")
			dns = open_resolv()
			sock2.sendto(query, (dns, 53))
			response, addr2 = sock2.recvfrom(2048)
			start = len(query)#start of answer
			tuple_data_dns = struct.unpack('!HHHHHH', response[:12])
			number_response = tuple_data_dns[3]
			entry_cache(query, response, start, number_response)
			sock.sendto(response,addr)
		else:
			#iterative
			print("***Iterative Query***")
			root = ['199.7.83.42']#ICANN server
			got = False
			response = iterate_query(root, query)
			if(response == -1):
				print("Cannot resolve");
				sock.sendto("-1".encode(),addr)
			else:
				sock.sendto(response,addr)
				
if __name__ == "__main__":
	main()
			
			
			
			

