from library import *
#DNS server runs on port 53
serverPort = 53

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
		
def parse_response(query,hostname,timeout,retry):
	server = open_resolv()
	sock = socket(AF_INET, SOCK_DGRAM)
	sock.sendto(query, (server, serverPort))
	number_queries, number_response, number_authority, number_additional, rcode, reply= send(sock,query,hostname,timeout,retry,1)
	start = len(query)#start of answer
	for i in range(number_response):
		if(reply[start+3] == 1):#A type query
			name,ip = get_ipv4(reply,start)
			print("Name:\t",name)
			print("Address: ",ip)
		
		elif(reply[start+3] == 28):#AAAA type query
			name,ip = get_ipv6(reply,start)
			print("Name:\t",name)
			print("Address: ",ip)
		
		elif(reply[start+3] == 2):#NS type query
			name,ns = get_NS(reply,start)
			print(name,"\tnameserver = ",ns)
			
		elif(reply[start+3] == 5):#CNAME type query
			name,cname = get_TXT(reply,start)
			print(name,"\tcanonical name = ",cname)
		
		elif(reply[start+3] == 6):#SOA type query
			name,pns,ram,sn,rfi,rti,el,mt = get_SOA(reply,start)
			print(name,"\n\torigin = ",pns, "\n\tmail addr = ",ram, "\n\tserial = ",sn, "\n\trefresh = ",rfi, "\n\tretry = ",rti, "\n\texpire = ",el, "\n\tminimum = ",mt)
			
		elif(reply[start+3] == 15):#MX type query
			name,mx = get_MX(reply,start)
			print(name,"\tmail exchanger = ",mx)
		
		elif(reply[start+3] == 16):#TXT type query
			name,text = get_TXT(reply,start)
			print(name,"\ttext = ",text)
		
		elif(reply[start+3] == 12):#PTR type query
			addr,name = get_PTR(reply,start)
			print(addr,"\tname = ",name)
			
		lent = reply[start+11]
		start += lent + 12

def send(sock,query,hostname,timeout,retry,current_retry):
	rcode,flag =1,0
	sock.settimeout(timeout)
	try:
		reply, addr = sock.recvfrom(2048)
	except Exception as e:#timeout
		if(current_retry < retry):
			print("**Retrying(doubling timeout))**")
			#timeout doubles
			return send(sock, query,hostname,timeout*2,retry,current_retry+1)
		else:
			print(";; connection timed out; no servers could be reached")
			sys.exit()
			
	try:
		flag = reply.decode()#if cannot resolve flag = -1
	except:
		pass
	if(flag == '-1'):
		print("** server can't find", hostname,":No answer")
		sys.exit()
	number_queries, number_response, number_authority, number_additional, rcode = data_packet_dns(reply)
	
	if rcode != 0:
		print("** server can't find", hostname,":No answer")
		sys.exit();
	#if rcode is zero then ok
	return number_queries, number_response, number_authority, number_additional, rcode, reply
	

def finalCall(hostname,type,recurse,timeout,retry):
	print("Server:		127.0.0.1")
	print("Address:	127.0.0.1#53")
	if type == 'PTR':
		hostname = ipaddress.ip_address(hostname).reverse_pointer
	query = constructQuery(hostname,type,"IN",recurse)
	types_implemented = ['A','AAAA','NS','MX','CNAME','SOA','TXT','PTR']
	if type in types_implemented:
		parse_response(query,hostname,timeout,retry)
	else:
		print("Not Implemted")
			
def main():
	hostname = sys.argv[len(sys.argv)-1]
	type = 'A'#default
	recurse = 1 #default
	timeout = 5
	retry = 4
	for i in range(1,len(sys.argv)-1):
		if(sys.argv[i] == "-norecurse"):
			recurse = 0 #iterative
			continue
		x = sys.argv[i].split('=',1)[0]
		y = sys.argv[i].split('=',1)[1]
		if(x=="-type"):
			type = y
		elif(x=="-timeout"):
			timeout = float(y);
		elif(x == "-retry"):
			retry = int(y)
			
	finalCall(hostname,type,recurse,timeout,retry)

if __name__ == "__main__":
	main()

