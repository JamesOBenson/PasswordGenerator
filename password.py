""" To execute: python3 password.py
#
# Copyright 2016 James Benson
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
#
"""

import getpass
from passlib.hash import pbkdf2_sha256
from passlib.hash import pbkdf2_sha512
from passlib.hash import sha512_crypt
#import passlib.pwd.generate as generate

print("Enter 1 for SHA256 salt size 16 hash")
print("Enter 2 for SHA512 salt size 16 hash")
print("Enter 3 for SHA512 (For ansible passwords)")
#print("Enter 4 to create a password -or- KeyFile")
X = int(input("Enter 0 to quit the program.\n"))
if X == 0:
    raise SystemExit

###  This is function is in beta and the function currently does not work. Once updated,
###  this function should work.
#if X == 4:
#    NSize = int(input("How long would you like your password? (# of characters)\n"))
#    NEntropy = int(input("How much entropy would you like your password? (Default: 48)\n"))
#    NCount = int(input("How many passwords would you like? (Default: 2)\n"))
#    generate(entropy=NEntropy, size=NSize, count=NCount, preset="diceware")
#    print("password is complete")

Y = str(input("Would you like the terminal to display the password typed? Y/N\n"))
if Y.lower() in ['y', 'ye', 'yes']:
    MY_PASSWORD = input("Please enter your password:\n")
if Y.lower() in ['n', 'no']:
    MY_PASSWORD = getpass.getpass("Please enter your secret password:")
if Y.lower() not in ['y', 'ye', 'yes', 'n', 'no']:
    raise SystemExit

if X == 1:
    MY_HASH = pbkdf2_sha256.encrypt(MY_PASSWORD, rounds=200000, salt_size=16)
    print("The verification of your password was:", pbkdf2_sha256.verify(MY_PASSWORD, MY_HASH))
    print("Your hash is: \n", MY_HASH)
elif X == 2:
    MY_HASH = pbkdf2_sha512.encrypt(MY_PASSWORD, rounds=200000, salt_size=16)
    print("The verification of your password was:", pbkdf2_sha512.verify(MY_PASSWORD, MY_HASH))
    print("Your hash is: \n", MY_HASH)
elif X == 3:
    MY_HASH = sha512_crypt.encrypt(MY_PASSWORD, rounds=200000, salt_size=16)
    print("The verification of your password was:", sha512_crypt.verify(MY_PASSWORD, MY_HASH))
    print("Your hash is: \n", MY_HASH)
else:
    print("Quitting")
    raise SystemExit
