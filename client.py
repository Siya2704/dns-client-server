from library import *
#public DNS server for Google DNS.
server = '127.0.0.1'
#DNS server runs on port 53
serverPort = 53
    
def getip(query,_type,hostname):
	number_queries, number_response, number_authority, number_additional, rcode, reply,start = send(query,hostname)
	if _type=='A':
		start = len(query) - 12#start of answer
		for i in range(number_response):
			ip = get_ipv4(reply,start)
			if reply[start+3] == 1:
				print("Name:\t",hostname)
				print("Address: ",ip)
			lent = reply[start+11]
			start += lent + 12
		
	elif _type=="AAAA":
		for i in range(0,number_response):
			ip = get_ipv6(reply,start)
			print("Name:\t",hostname)
			print("Address: ",ip)
			start +=28

def type_NS(query,_type,hostname):
	number_queries, number_response, number_authority, number_additional, rcode, reply,start = send(query,hostname)	
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
			if x in range(0, 16):
				res += "."
			else:
				res += chr(reply[i])
		if length < k:
			pointer = reply[beg+length-1] - 12
			end = k - length
			for i in range (pointer,pointer+end):
				x = reply[i]
				if x in range(0, 16):
					res += "."
				else:
					res += chr(reply[i])
			 
		if a == 12 and b == 192: #ie 0c
			print(hostname,"\tnameserver = ",res+"."+hostname+".")
		else:
			print(hostname,"\tnameserver = ",res+".")
		y+=12+length
         
def type_MX(query,_type,hostname):
	number_queries, number_response, number_authority, number_additional, rcode, reply,start = send(query,hostname)
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
			if x in range(0, 16):
				res += "."
			else:
				res += chr(reply[i])
		if length < k:
			pointer = reply[beg+length-1] -12
			end = k - length
			for i in range (pointer,pointer+end+1):
				x = reply[i]
				if x in range(0, 16):
					res += "."
				else:
					res += chr(reply[i])
					
		if a1 == 12 and b1 == 192: #ie 0c
			print(hostname,"\tmail exchanger = ",res+"."+hostname+".")
		else:
			print(hostname,"\tmail exchanger = ",res+".")
		y+=14+length


def type_CNAME(query,_type,hostname):
	number_queries, number_response, number_authority, number_additional, rcode, reply,start = send(query,hostname)
	y = 0
	beg = start+12
	for i in range(0,number_response):
		length = reply[start+11+y]
		res =""
		for i in range (beg+y,beg+y+length-1):
			x = reply[i]
			if x == 192:#next is pointer
				pointer = reply[i+1] - 11 #-12
				j = pointer
				while(1):
					k = reply[j]
					if k == 0:
						break;
					if k in range(1, 16):
						res += "."
					else:
						res += chr(reply[j])
					j += 1
					
			elif x in range(0, 16):
				res += "."
			else:
				res += chr(reply[i])
		print(hostname,"\tcanonical name = "+res+"")
		y+=12+length	
	
def send(query,hostname):
	rcode,retry,flag =1,0,0
	sock = socket(AF_INET, SOCK_DGRAM)
	while rcode != 0 and retry < 10:
		if(retry != 0):
			print("**Retrying**")
		sock.sendto(query, (server, serverPort))
		reply, addr = sock.recvfrom(2048)
		try:
			#data from cache
			lst = reply.decode()
			lst = eval(lst)# Convert decoded data into list
			if(lst[0] =='found'):
				lst = lst[1]
			print("From cache")
			for i in lst:
				print("Name:\t",hostname)
				print("Address: ",i)
			flag = 1
		except:
			pass
		if flag == 1:#if in cache
			sys.exit()
		number_queries, number_response, number_authority, number_additional, rcode, reply = data_packet_dns(reply)
		retry += 1
	if rcode != 0:
		print("** server can't find", hostname,":No answer")
		sys.exit('-');
	#if rcode is zero then ok
	start = len(query) - 12#start of answer
	return number_queries, number_response, number_authority, number_additional, rcode, reply,start
	

def finalCall(hostname,type,recurse):
	print("Server:		-----")#127.0.0.53
	print("Address:	-----#53")
	print("\nNon-authoritative answer:")
	
	query = constructQuery(hostname,type,"IN",recurse)
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
	hostname = sys.argv[len(sys.argv)-1]
	type = 'A'#default
	recurse = 1 #default
	for i in range(1,len(sys.argv)-1):
		if(sys.argv[i] == "norecurse"):
			recurse = 0 #iterative
			continue
		x = sys.argv[i].split('=',1)[0]
		y = sys.argv[i].split('=',1)[1]
		if (x=="-type"):
			type = y
		elif (x=="-timeout"):
			timeout = y

	finalCall(hostname,type,recurse)

if __name__ == "__main__":
	main()


