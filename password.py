import getpass
from passlib.hash import pbkdf2_sha256
from passlib.hash import pbkdf2_sha512
from passlib.hash import sha512_crypt
#import passlib.pwd.generate as generate

x = int(input("Enter 1 for SHA256 salt size 16 hash\nEnter 2 for SHA512 salt size 16 hash\nEnter 3 for SHA512 (For ansible passwords)\nEnter 4 to create a password -or- KeyFile\nEnter 0 to quit the program.\n"))
if x ==0:
	raise SystemExit
if x ==4:
	nsize=int(input("How long would you like your password? (# of characters)\n"))
	nentropy=int(input("How much entropy would you like your password? (Default: 48)\n"))
	ncount=int(input("How many passwords would you like? (Default: 2)\n"))
	generate(entropy=nentropy, size=nsize, count=ncount,preset="diceware")
	print("password is complete")

y = str(input("Would you like the terminal to display the password typed? Y/N\n"))
if y.lower() in ['y','ye','yes']:
	password = input("Please enter your password:\n")
if y.lower() in ['n','no']:
	password = getpass.getpass("Please enter your secret password:")
if y.lower() not in ['y','ye','yes','n','no']:
	raise SystemExit

if x == 1:
	hash = pbkdf2_sha256.encrypt(password, rounds=200000, salt_size=16)
	print("The verification of your password was:", pbkdf2_sha256.verify(password, hash))
	print("Your hash is: \n", hash)
elif x == 2:
	hash = pbkdf2_sha512.encrypt(password, rounds=200000, salt_size=16)
	print("The verification of your password was:", pbkdf2_sha512.verify(password, hash))
	print("Your hash is: \n", hash)
elif x == 3:
	hash = sha512_crypt.encrypt(password, rounds=200000, salt_size=16)
	print("The verification of your password was:", sha512_crypt.verify(password, hash))
	print("Your hash is: \n", hash)
else:
	print("Quitting");
	raise SystemExit
