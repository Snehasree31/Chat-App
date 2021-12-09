import socket
from cryptography.fernet import Fernet
import pickle
import random
import hashlib
import hmac

c =socket.socket()
IP='127.0.0.1'
port=4664
try:
	c.connect((IP,port))
	print('Connected to Server')
except:
        print("Connection Failed, Try Again")

lst= []
while 1:
#Receving from Server
	data=(c.recv(1024))

	data = pickle.loads(data)
	key = Fernet(data[0])
	encmsg = data[1]
	sha512= data[3]
	salt = data[2]
	hmac1= data[4]

	decmsg = (key.decrypt(encmsg)).decode('utf-8')

	inp_sha512=hashlib.sha512(decmsg.encode())
	inp_sha512=inp_sha512.hexdigest()

	recv_hmac= hmac1
	hmac2 = hmac.new(key=salt.encode(),msg=decmsg.encode(),digestmod="sha512")
	hmac2= hmac2.hexdigest()

	#Confirming Authentication
	if (recv_hmac == hmac2):
		#SHA-512 Integrity
		if (inp_sha512==sha512):
			print("Server: ",decmsg)
		else:
			print("The Connection has been Tampered")
	else:
		print ("Invaid Authentication")


#Sending msg to Server
	print("Client(You): ",end='')
	info =input()
	digits ="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

	#Symmetric key Encryption
	key=Fernet.generate_key()
	lst.append(key)
	fernet_key =Fernet(key)
	ency_info=fernet_key.encrypt(info.encode())
	lst.append(ency_info)

	#Generating salt
	salt=[]
	for i in range(12):
		salt.append(random.choice(digits))
	app_salt= (''.join(salt))
	lst.append(app_salt)

	#SHA-512 integrity
	sha512=hashlib.sha512(info.encode())
	sha512=sha512.hexdigest()
	lst.append(sha512)

	#HMAC Authentication
	hmac1 = hmac.new(key=app_salt.encode(),msg=info.encode(),digestmod="sha512")
	hmac1 = hmac1.hexdigest()
	lst.append (hmac1)

	data=pickle.dumps(lst)
	c.send(data)
	lst.clear()

c.close()
