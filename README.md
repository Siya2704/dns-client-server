Server runs on `127.0.0.51`
make entry into `"/etc/resolv.conf"`:`nameserver:127.0.0.51`

To run the server+client run command 
- `sudo python3 server.py`  to start the server
- `./run.sh` which contains few queries for server just to test the server

if you want to provide other queries then run command :
- `python3 client.py [-option][name]`
- options implemented are -timeout, -retry, -type, -norecurse
- supported types = ['A','AAAA','NS','MX','CNAME','SOA','TXT','PTR']

