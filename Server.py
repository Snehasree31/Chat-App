import socket
from cryptography.fernet import Fernet
import pickle
import random
import hashlib
import hmac

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
IP='127.0.0.1'
port=4664
s.bind((IP,port))
print("Server listening to client")
s.listen(1)
conn,addr=s.accept()
print("Connected with Client")

lst = []
while 1:
#Sending msg to Client
	print("Server(You): ",end='') 
	info = input()
	digits ="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

	#Symmetric key encryption
	key=Fernet.generate_key()
	lst.append(key) #0
	fernet_key =Fernet(key)
	ency_info=fernet_key.encrypt(info.encode())
	lst.append(ency_info) #1

	#generating salt
	salt=[]
	for i in range(12):
		salt.append(random.choice(digits))
	app_salt= (''.join(salt))
	lst.append(app_salt) #2

	#SHA-512 integrity
	sha512=hashlib.sha512(info.encode())
	sha512=sha512.hexdigest()
	lst.append(sha512) #3

	#HMAC Authentication
	hmac1= hmac.new(key=app_salt.encode(),msg=info.encode(),digestmod="sha512")
	hmac1=hmac1.hexdigest()
	lst.append(hmac1) #4

	data=pickle.dumps(lst)
	conn.send(data)
	lst.clear()


#Receving from Client
	recv_info=(conn.recv(1024))

	recv_info = pickle.loads(recv_info)
	key =Fernet( recv_info[0])
	encmsg = recv_info[1]
	sha512 = recv_info[3]
	salt = recv_info[2]
	hmac1= recv_info[4]

	decryptmsg = (key.decrypt(encmsg)).decode('utf-8')

	inp_sha512=hashlib.sha512(decryptmsg.encode())
	inp_sha512=inp_sha512.hexdigest()

	recv_hmac= hmac1
	hmac2 =hmac.new(key=salt.encode(),msg=decryptmsg.encode(),digestmod="sha512")
	hmac2 =hmac2.hexdigest()

	#Confirming Authentication
	if (recv_hmac == hmac2):
		#SHA-512 Integrity
		if (inp_sha512==sha512):
			print("Client: ",decryptmsg)
		else:
			print("The Connection has been Tampered")
	else:
		print ("Invaid Authentication") 
conn.close()
