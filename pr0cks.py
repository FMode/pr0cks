# Author: Nicolas VERDIER (contact@n1nj4.eu)
# This file is part of pr0cks.
#
# pr0cks is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# pr0cks is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with pr0cks.  If not, see <http://www.gnu.org/licenses/>.

import sys
import io
import time
import struct
import os
import asyncore
import socket
import socks
import argparse
import traceback
import logging
import threading
from socks import set_default_proxy
logging.basicConfig(stream=sys.stderr, level=logging.WARNING)
import binascii
from collections import OrderedDict
import ipaddress
#import pypac
import pypac as _pypac

class PACFile():
	def __init__(self,pacfile):
		self.cache=dict()
		self.pacfile=pacfile
		self.lock=threading.Lock()
	
	def find_proxy_for_url(self,url, host):
		e=self.cache.get(url)
		if e==None:
			with self.lock:
				ret=self.pacfile.find_proxy_for_url(url, host)
			self.cache[url]=ret
			return ret
		else:
			return self.cache[url]
		

class pypac():
	pacfile=None
	@staticmethod
	def get_pac(*args, **kwargs):	
		pacfile= PACFile(_pypac.get_pac(*args, **kwargs))
		return pacfile


import dns.resolver
dns_resolver = dns.resolver.Resolver()
#import unittest.mock
#dns_resolver = unittest.mock.Mock()
#dns_resolver.search=["mydomain.de","mydomain2.de"]

dnslib_imported=False
dns_cache_lock = threading.Lock()
dns_cache=dict()
dns_cache[0]="localhost"
dns_cache[53]="dns stub resolver"
#dns_cache[1]="DO_NOT_USE"
dns_cache_rev=dict()
DNS_CACHE_SIZE=1000

def display(msg):
	msg=msg.strip()
	if msg.startswith("[-]"):
		print("\033[31m[-]\033[0m"+msg[3:])
	elif msg.startswith("[+]"):
		print("\033[32m[+]\033[0m"+msg[3:])
	elif msg.startswith("[i]"):
		print("\033[1;30m[i]\033[0m"+msg[3:])
	else:
		print(msg)
	sys.stdout.flush()

try:
	from dnslib import DNSRecord, QTYPE, RR, A
	from dnslib.server import DNSServer,DNSHandler,BaseResolver,DNSLogger
	class ProxyResolver(BaseResolver):
		def __init__(self,address,port):
			self.address = address
			self.port = port

		def resolve(self,request,handler):
			if handler.protocol == 'udp':
				proxy_r = request.send(self.address,self.port)
			else:
				proxy_r = request.send(self.address,self.port,tcp=True)
			reply = DNSRecord.parse(proxy_r)
			return reply
		
	class PACDNSHandler(DNSHandler):
  
		def get_reply(self,data):
			global dns_cache
			global dns_cache_rev
			global dns_cache_lock
			global args
			global pac
			host,port = self.server.resolver.address,self.server.resolver.port
			request = DNSRecord.parse(data)
			#print("----------------------------------request-----------------------------")
			#print(DNSRecord.parse(data))
			#print("----------------------------------------------------------------------")
			response=None

			if self.protocol == 'tcp':
				data = struct.pack("!H",len(data)) + data
				response = send_tcp(data,host,port)
				response = response[2:]
			else:
				response = send_udp(data,host,port)
				#print(response)

			response_parsed=DNSRecord.parse(response)
			#print(response_parsed)
			
			if response_parsed.a.rdata!=None:
				return response
			else:
				domain=str(request.q.qname)
				found=False
				hostname=""
				for e in dns_resolver.search:
					if str(e) in domain:
						hostname=domain.replace(str(e), "", 1)
						found=True
						break
				if found:
					return data
				else:
					#print("!!!!!!!!!!!"+domain)
					qtype=str(QTYPE.get(request.q.qtype))
					index=domain+"/"+qtype
	
					p=pac.find_proxy_for_url(domain, domain).split(' ')
					#print(p)		 
					if p[0]=="DIRECT":
						display("no dns reply for %s - pac states as 'DIRECT'"%(domain))
						return data
					else:
						#print("------------reply!!!--------------")
						reply=request.reply()
						with dns_cache_lock:
							d=dns_cache_rev.get(domain)
							i=0
							if d==None:
								i=len(dns_cache)
								if i in dns_cache:
									i=i+1
								if args.verbose:
									display("[i] dns_cache entry created: %s - %s"%(domain,str(ipaddress.IPv4Address(i)).replace("0",args.fake_net_nr,1)))
								dns_cache_rev[domain]=i
								dns_cache[i]=domain
							else:
								i=d
						if i==0:
							display("[i] already replied with IP from DNS!")
							return data
						else:
							#print("iiii:"+str(i))
							reply.add_answer(RR(domain,QTYPE.A,rdata=A(str(ipaddress.IPv4Address(i)).replace("0",args.fake_net_nr,1)),ttl=60))
							return reply.pack()
			
	def send_tcp(data,host,port):
		"""
			Helper function to send/receive DNS TCP request
			(in/out packets will have prepended TCP length header)
		"""
		sock = None
		try:
			sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
			sock.settimeout(5)
			sock.connect((host,port))
			sock.sendall(data)
			response = sock.recv(8192)
			length = struct.unpack("!H",bytes(response[:2]))[0]
			while len(response) - 2 < length:
				response += sock.recv(8192)
			return response
		finally:
			if (sock is not None):
				sock.close()
			return None
	def send_udp(data,host,port):
		"""
			Helper function to send/receive DNS UDP request
		"""
		sock = None
		response=None
		try:
			sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
			#sock.settimeout(5)
			sock.sendto(data,(host,port))
			response,server = sock.recvfrom(8192)
		#except Exception as e:
			#print(e)
		finally:
			if (sock is not None):
				sock.close()
			return response	 

	class PassthroughDNSHandler(DNSHandler):
		def get_reply(self,data):
			global dns_cache
			global args

			host,port = self.server.resolver.address,self.server.resolver.port
			request = DNSRecord.parse(data)
			print("----------------------------------request-----------------------------")
			print(request)
			print("----------------------------------------------------------------------")

			domain=str(request.q.qname)
			qtype=str(QTYPE.get(request.q.qtype))
			index=domain+"/"+qtype

			if not args.no_cache and index in dns_cache:
				if time.time()<dns_cache[index][0]:
					if args is not None and args.verbose:
						try:
							display("[i] %s served value from cache: %s"%(index, ', '.join([x.rdata for x in dns_cache[index][1]])))
						except:
							pass
					rep=request.reply()
					rep.add_answer(*dns_cache[index][1])
					return rep.pack()
			if args is not None and args.verbose:
				display("[i] domain %s requested using TCP server %s"%(domain, args.dns_server))
			data = struct.pack("!H",len(data)) + data
			response = send_tcp(data,host,port)
			response = response[2:]
			reply = DNSRecord.parse(response)
			print("------------------------------------reply-----------------------------")
			print(reply)
			print("----------------------------------------------------------------------")
			if args.verbose:
				try:
					display("[i] %s %s resolve to %s"%(domain, qtype, ', '.join([x.rdata for x in reply.rr])))
				except:
					pass
			ttl=3600
			try:
				ttl=reply.rr[0].ttl
			except Exception:
				try:
					ttl=reply.rr.ttl
				except Exception:
					pass
			dns_cache[index]=(int(time.time())+ttl, reply.rr)
			if len(dns_cache)>DNS_CACHE_SIZE:
				dns_cache.popitem(last=False)
			return response

	def send_tcp(data,host,port):
		"""
			Helper function to send/receive DNS TCP request
			(in/out packets will have prepended TCP length header)
		"""
		sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
		sock.settimeout(5)
		sock.connect((host,port))
		sock.sendall(data)
		response = sock.recv(8192)
		length = struct.unpack("!H",bytes(response[:2]))[0]
		while len(response) - 2 < length:
			response += sock.recv(8192)
		sock.close()
		return response
	
	dnslib_imported=True
except ImportError:
	display("[-] WARNING: The following dependency is needed to proxify DNS through tcp: pip install dnslib")


#Python socket module does not have this constant
SO_ORIGINAL_DST = 80
class Socks5Conn(asyncore.dispatcher):
	def __init__(self, sock=None, map=None, conn=True, verbose=False, pac_tuple=None):
		if pac_tuple==None:
			dns_cache=None
			dns_cache_lock=None
			pac=None
			username=None
			password=None
			fake_net_nr=""
		else:
			(dns_cache, dns_cache_lock, pac, username, password, fake_net_nr)=pac_tuple
		self.out_buffer=b""
		self.verbose=verbose
		self.allsent=False
		if conn is True:
			#get the original dst address and port
			odestdata = sock.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
			_, port, a1, a2, a3, a4 = struct.unpack("!HHBBBBxxxxxxxx", odestdata)
			address = "%d.%d.%d.%d" % (a1, a2, a3, a4)
			if dns_cache != None:
				ipaddr=address
				if fake_net_nr in address:
					n=int(ipaddress.IPv4Address(address.replace(fake_net_nr,"0",1)))
					with dns_cache_lock:
						elem=dns_cache.get(n)
					if elem!=None:
						address=elem					
				t=pac.find_proxy_for_url(address, address).split(' ')
				if t[0]=="PROXY":
					p_ip, p_port= t[1].split(":")
					self.conn_sock = socks.socksocket()
					self.conn_sock.set_proxy(proxy_type=socks.PROXY_TYPE_HTTP, addr=p_ip, port=int(p_port), rdns=True, username=username, password=password)	
					if self.verbose:
						display('[+] Forwarding incoming connection from %s to %s %s through the proxy %s:%s' % (repr(sock.getpeername()), address, (ipaddr, port), p_ip, p_port))
				else:
					self.conn_sock = socks.socksocket()
					self.conn_sock.set_proxy(proxy_type=None)	
					if self.verbose:
						display('[+] Forwarding incoming connection from %s to %s (%s)' % (repr(sock.getpeername()), address, (ipaddr, port)))
					
			else:
				if self.verbose:
					display('[+] Forwarding incoming connection from %s to %s through the proxy' % (repr(sock.getpeername()), (address, port)))
				self.conn_sock = socks.socksocket()

			#connect to the original dst :
			#self.conn_sock.settimeout(15)
			self.conn_sock.connect((address, port))

			self.sock_class=Socks5Conn(sock=self.conn_sock, conn=self,pac_tuple=pac_tuple) #add a dispatcher to handle the other side
		else:
			self.sock_class=conn
			self.conn_sock=None
		asyncore.dispatcher.__init__(self, sock, map)

	def initiate_send(self):
		num_sent = 0
		num_sent = asyncore.dispatcher.send(self, self.out_buffer[:4096])
		self.out_buffer = self.out_buffer[num_sent:]

	def handle_write(self):
		self.initiate_send()

	def writable(self):
		return (self.allsent or len(self.out_buffer)>0)

	def send(self, data):
		#if self.debug:
		#	self.log_info('sending %s' % repr(data))
		if data:
			self.out_buffer += data
		else:
			self.allsent=True
		#self.initiate_send()

	def handle_read(self):
		data = self.recv(8192)
		self.sock_class.send(data)

	def handle_close(self):
		leftover_size=len(self.sock_class.out_buffer)
		while leftover_size>0 :
			logging.debug("sending %s leftover data"%leftover_size)
			self.sock_class.initiate_send()
			leftover_size=len(self.sock_class.out_buffer)

		self.sock_class.close()
		self.close()

	def handle_error(self):
		t, v, tb = sys.exc_info()
		display("[-] Socks5conn Error: %s : %s\n%s"%(t,v, tb))



class Pr0cks5Server(asyncore.dispatcher):
	def __init__(self, host, port, verbose=None, pac_tuple=None):
		asyncore.dispatcher.__init__(self)
		self.verbose=verbose
		self.pac_tuple=pac_tuple
		self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
		self.set_reuse_addr()
		self.bind((host, port))
		self.listen(20)
		

	def handle_accept(self):
		pair = self.accept()
		if pair is not None:
			sock, addr = pair
			self.sock=sock
			handler = Socks5Conn(sock, verbose=self.verbose,pac_tuple=self.pac_tuple)
	def handle_close(self):
		self.sock.close()
		self.close()
	def handle_error(self):
		t, v, tb = sys.exc_info()
		display("[-] %s : %s"%(t,v))

		

args=None
if __name__=='__main__':
	parser = argparse.ArgumentParser(prog='procks', description="Transparent SOCKS5/SOCKS4/HTTP_CONNECT Proxy")
	parser.add_argument('--proxy', default="SOCKS5:127.0.0.1:1080", help="proxytype:ip:port to forward our connections through. proxytype can be SOCKS5, SOCKS4, HTTP or PAC")
	parser.add_argument('-p', '--port', type=int, default=10080, help="port to bind the transparent proxy on the local socket (default 10080)")
	parser.add_argument('-n', '--nat', action='store_true', help="set bind address to 0.0.0.0 to make pr0cks work from a netfilter FORWARD rule instead of OUTPUT")
	parser.add_argument('-v', '--verbose', action="store_true", help="print all the connections requested through the proxy")
	parser.add_argument('-c', '--no-cache', action="store_true", help="don't cache dns requests")
	parser.add_argument('--username', default=None, help="Username to authenticate with to the server. The default is no authentication.")
	parser.add_argument('--password', default=None, help="Only relevant when a username has been provided")
	parser.add_argument('--dns-port', default=1053, type=int, help="dns port to listen on (default 1053)")
	parser.add_argument('--dns-server', default="", help="ip:port of the DNS server to forward all DNS requests to using TCP through the proxy (otherwise use system)")#208.67.222.222:53
	parser.add_argument('--rdns', default="True", help="rdns setting of socks module")
	parser.add_argument('--fake_net_nr', default="172", help="network number for fake net")
	args=parser.parse_args()

	t=None
	ptype,proxy_addr=args.proxy.split(":",1)
	if ptype.upper()=="SOCKS5":
		ptype,proxy_addr,proxy_port=args.proxy.split(":",2)
		t=socks.PROXY_TYPE_SOCKS5
	elif ptype.upper()=="SOCKS4":
		ptype,proxy_addr,proxy_port=args.proxy.split(":",2)
		t=socks.PROXY_TYPE_SOCKS4
	elif ptype.upper()=="HTTP":
		ptype,proxy_addr,proxy_port=args.proxy.split(":",2)
		t=socks.PROXY_TYPE_HTTP
	elif ptype.upper()=="PAC":
		t=socks.PROXY_TYPE_HTTP
		proxy_port=0		
	else:
		display("[-] --proxy : unknown proxy type %s"%ptype)
		exit(1)

	#bind_address="127.0.0.1"
	bind_address="127.0.0.1"
	if args.nat:
		bind_address="0.0.0.0"
	if dnslib_imported:
		try:
			if args.dns_server=="":
				dns_srv = dns_resolver.nameservers[0]
				dns_port = dns_resolver.port
			else:
				dns_srv, dns_port=args.dns_server.split(':',1)
			dns_port=int(dns_port)
		except Exception as e:
			display("[-] %s"%e)
			display("[-] Invalid dns server : %s"%args.dns_server)
			exit(1)
		resolver = ProxyResolver(dns_srv,dns_port)
		
		handler = None
		if ptype.upper()=="PAC":
			handler = PACDNSHandler
		else:
			handler = PassthroughDNSHandler # if args.passthrough else DNSHandler

		logger = DNSLogger("request,reply,truncated,error", False)
		udp_server = DNSServer(resolver,
							   port=args.dns_port,
							   address=bind_address,
							   logger=logger,
							   handler=handler)
		udp_server.start_thread()
		display("[+] DNS server started on %s:%s forwarding all DNS trafic to %s:%s using TCP"%(bind_address, args.dns_port, dns_srv, dns_port))
		time.sleep(1)
	
	#dns for proxy pac is avaiable now(!)
	pac = pypac.get_pac(url='http://pacproxy.vw.vwg/pac/vw-intproxy.pac')
	try:
		proxy_port=int(proxy_port)
	except Exception:
		display("[-] --proxy : invalid port %s"%proxy_port)
		exit(1)

	if args.username:
		if not args.password:
			exit("username provided but without password !")
		display("[+] Provided credentials are %s:%s"%(args.username, args.password[0:3]+"*"*(len(args.password)-3)))
	#socks.setdefaultproxy(proxytype=t, addr=proxy_addr, port=proxy_port, username=args.username, password=args.password,dns_cache=dns_cache,dns_cache_rev=dns_cache_rev)
	socks.set_default_proxy(proxy_type=t, addr=proxy_addr, port=proxy_port, rdns=args.rdns,username=args.username, password=args.password)
	display("[+] Forwarding all TCP traffic received on %s:%s through the %s proxy on %s:%s"%(bind_address, args.port, ptype, proxy_addr, proxy_port))
	display("[i] example of rule you need to have:")
	display("iptables -t nat -A OUTPUT -o eth0 -p tcp -m tcp !-d <proxy_server> -j REDIRECT --to-ports %s"%args.port)
	display("iptables -t nat -A OUTPUT -o eth0 -p udp -m udp --dport 53 -j REDIRECT --to-ports %s"%args.dns_port)
	display("[i] Tip to avoid leaks : Block IPv6. For ipv4 put a DROP policy on OUTPUT and only allow TCP to your socks proxy. cf. the iptables.rules example file")


	try:
		server = Pr0cks5Server(bind_address, args.port, verbose=args.verbose, pac_tuple=(dns_cache, dns_cache_lock,pac, args.username, args.password, args.fake_net_nr))

		asyncore.loop()
	except KeyboardInterrupt:
		sys.stdout.write("\n")
		sys.exit(0)
	except Exception as e:
		sys.stderr.write(traceback.format_exc())
		sys.exit(1)
