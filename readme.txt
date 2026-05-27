Issue 5:​

1.vi /etc/dnsmasq.conf​

port=5353​

listen-address=192.168.168.1​

bind-interfaces​

no-resolv​

no-hosts​

no-poll​

cache-size=1000​

log-queries​

log-facility=-​

server=127.0.0.1#5354​

add-subnet​

(and restart dnsmasq daemon)​

​

2. python3 issue5.py​

​