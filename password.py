""" To execute: python password.py
"""

import getpass
from passlib.hash import pbkdf2_sha256
from passlib.hash import pbkdf2_sha512
from passlib.hash import sha512_crypt
#import passlib.pwd.generate as generate

print("Enter 1 for SHA256 salt size 16 Hash")
print("Enter 2 for SHA512 salt size 16 Hash")
print("Enter 3 for SHA512 (For ansible passwords)")
#print("Enter 4 to create a Password -or- KeyFile")
X = int(input("Enter 0 to quit the program.\n"))
if X == 0:
    raise SystemExit
    
###  This is function is in beta and the function currently does not work. Once updated,
###  this function should work.
#if X == 4:
#    NSize = int(input("How long would you like your Password? (# of characters)\n"))
#    NEntropy = int(input("How much entropy would you like your Password? (Default: 48)\n"))
#    NCount = int(input("How many passwords would you like? (Default: 2)\n"))
#    generate(entropy=NEntropy, size=NSize, count=NCount, preset="diceware")
#    print("Password is complete")

Y = str(input("Would you like the terminal to display the Password typed? Y/N\n"))
if Y.lower() in ['y', 'ye', 'yes']:
    Password = input("Please enter your Password:\n")
if Y.lower() in ['n', 'no']:
    Password = getpass.getpass("Please enter your secret Password:")
if Y.lower() not in ['y', 'ye', 'yes', 'n', 'no']:
    raise SystemExit

if X == 1:
    Hash = pbkdf2_sha256.encrypt(Password, rounds=200000, salt_size=16)
    print("The verification of your Password was:", pbkdf2_sha256.verify(Password, Hash))
    print("Your Hash is: \n", Hash)
elif X == 2:
    Hash = pbkdf2_sha512.encrypt(Password, rounds=200000, salt_size=16)
    print("The verification of your Password was:", pbkdf2_sha512.verify(Password, Hash))
    print("Your Hash is: \n", Hash)
elif X == 3:
    Hash = sha512_crypt.encrypt(Password, rounds=200000, salt_size=16)
    print("The verification of your Password was:", sha512_crypt.verify(Password, Hash))
    print("Your Hash is: \n", Hash)
else:
    print("Quitting")
    raise SystemExit
