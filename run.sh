#!/bin/sh

echo "python3 client.py norecurse -type=A moldtelecom.md"
python3 client.py norecurse -type=A moldtelecom.md

echo "\n\npython3 client.py norecurse -type=AAAA moldtelecom.md"
python3 client.py norecurse -type=AAAA moldtelecom.md

echo "\n\npython3 client.py norecurse -type=NS moldtelecom.md"
python3 client.py norecurse -type=NS moldtelecom.md

echo "\n\npython3 client.py norecurse -type=CNAME moldtelecom.md"
python3 client.py norecurse -type=CNAME moldtelecom.md

echo "\n\npython3 client.py norecurse -type=TXT moldtelecom.md"
python3 client.py norecurse -type=TXT moldtelecom.md

echo "\n\npython3 client.py norecurse -type=MX moldtelecom.md"
python3 client.py norecurse -type=MX moldtelecom.md

echo "\n\npython3 client.py norecurse -type=SOA moldtelecom.md"
python3 client.py norecurse -type=SOA moldtelecom.md

echo "\n\npython3 client.py -type=PTR 142.250.192.4"
python3 client.py -type=PTR 142.250.192.4

echo "\n\npython3 client.py norecurse yf1.yahoo.com"
python3 client.py norecurse yf1.yahoo.com

echo "\n\npython3 client.py norecurse -type=A -retry=3 -timeout=2 yao.com"
python3 client.py norecurse -type=A -retry=3 -timeout=2 yao.com

echo "\n\npython3 client.py norecurse -type=A -retry=3 -timeout=2 google.com"
python3 client.py norecurse -type=A -retry=3 -timeout=2 google.com

echo "\n\npython3 client.py norecurse -type=AAAA timeout=2 yahoo.com"
python3 client.py norecurse -type=AAAA timeout=2 yahoo.com

echo "\n\npython3 client.py norecurse yahoo.com"
python3 client.py norecurse yahoo.com

echo "\n\npython3 client.py norecurse -type=NS timeout=2 yahoo.com"
python3 client.py norecurse -type=NS timeout=2 yahoo.com

echo "\n\npython3 client.py norecurse -type=SOA yahoo.com"
python3 client.py norecurse -type=SOA yahoo.com

echo "\n\npython3 client.py norecurse -type=SOA yahoo.com"
python3 client.py norecurse -type=SOA yahoo.com

echo "\n\npython3 client.py norecurse -type=SOA microsoft.com"
python3 client.py norecurse -type=SOA microsoft.com

echo "\n\npython3 client.py norecurse -type=CNAME www.youtube.com"
python3 client.py norecurse -type=CNAME www.youtube.com

echo "\n\npython3 client.py -type=CNAME www.shakthimaan.com"
python3 client.py -type=CNAME www.shakthimaan.com

echo "\n\npython3 client.py norecurse -type=MX gmail.com"
python3 client.py norecurse -type=MX gmail.com

echo "\n\npython3 client.py norecurse -type=MX coep.ac.in"
python3 client.py norecurse -type=MX coep.ac.in

echo "\n\npython3 client.py norecurse www.coep.org.in"

echo "\n\npython3 client.py norecurse -type=NS coep.org.in"
python3 client.py norecurse -type=NS coep.org.in

echo "\n\npython3 client.py norecurse -type=A -retry=3 -timeout=2 apple.com"
python3 client.py norecurse -type=A -retry=3 -timeout=2 apple.com

echo "\n\npython3 client.py norecurse -type=TXT -timeout=2 apple.com"
python3 client.py norecurse -type=TXT -timeout=2 apple.com

echo "\n\npython3 client.py norecurse -type=MX -timeout=2 apple.com"
python3 client.py norecurse -type=MX -timeout=2 apple.com

echo "\n\npython3 client.py -type=PTR timeout=2 2404:6800:4009:827::2004"
python3 client.py -type=PTR timeout=2 2404:6800:4009:827::2004


echo "\n\npython3 client.py norecurse -type=A moldtelecom.md"
python3 client.py norecurse -type=A moldtelecom.md

echo "\n\npython3 client.py -type=CNAME www.shakthimaan.com"
python3 client.py -type=CNAME www.shakthimaan.com

