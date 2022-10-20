#!/bin/python3

#Seriously if you haven't checked out TCM Security at all, you need to - their courses are fantastic 

from pwn import *
import sys


def Usage():
  print("Proper syntax for hashkitty: ./hashkitty.py [RAW_HASH] [PATH_TO_WORDLIST]")

if len(sys.argv) != 3:
  print("Error: Invalid arguments")
  Usage()
  sys.exit()

print(r""" 
             /\     /\
            {  `---'  }
            {  O   O  }
            ~~>  V  <~~
             \  \|/  /
              `-----'__
              /     \  `^\_
             {       }\ |\_\_   W
             |  \_/  |/ /  \_\_( )
              \__/  /(_E     \__/
                (  /
                 MM
       """)
       
version = "1.0"
update_date = "2022-10-20"
print("\n**** hashkitty [ver {}] created by Hotel Six on [{}] (latest update {} on {}) ****".format(version, update_date, version, update_date))
print("* * Credit to: Riley Kidd (aka Neut) & TCM Security * *\n \n")

if len(sys.argv[1]) == 32:
  hash_type = "MD5"
elif len(sys.argv[1]) == 40:
  hash_type = "SHA1"
elif len(sys.argv[1]) == 56:
  hash_type = "SHA224"
elif len(sys.argv[1]) == 64:
  hash_type = "SHA256"
elif len(sys.argv[1]) == 96:
  hash_type = "SHA384"
elif len(sys.argv[1]) == 128:
  hash_type = "SHA512"
else:
  print("Error: Invalid hash length")
  sys.exit()

wanted_hash = sys.argv[1]
password_file = sys.argv[2] 
attempts = 0

if hash_type == "MD5":
  with log.progress("Attempting to break: {} hash [{}] using the {} file...\n".format(hash_type, wanted_hash, password_file)) as p:
    with open(password_file, "r", encoding='latin-1') as password_list: #encoding 
      for password in password_list:
        password = password.strip("\n").encode('latin-1') #stripping new line
        password_hash = md5sumhex(password)
        p.status("[{}] {} == {}".format(attempts, password.decode('latin-1'), password_hash))
        if password_hash == wanted_hash:
          p.success("Password hash found after {} attempts. [{}] hashes to the {} hash of: {}".format(attempts, password.decode('latin-1'), hash_type, password_hash))
          exit()
        attempts += 1
      p.failure("Password hash not found!")
      
elif hash_type == "SHA1":
  with log.progress("Attempting to break: {} hash [{}] using the {} file...\n".format(hash_type, wanted_hash, password_file)) as p:
    with open(password_file, "r", encoding='latin-1') as password_list: #encoding 
      for password in password_list:
        password = password.strip("\n").encode('latin-1') #stripping new line
        password_hash = sha1sumhex(password)
        p.status("[{}] {} == {}".format(attempts, password.decode('latin-1'), password_hash))
        if password_hash == wanted_hash:
          p.success("Password hash found after {} attempts. [{}] hashes to the {} hash of: {}".format(attempts, password.decode('latin-1'), hash_type, password_hash))
          exit()
        attempts += 1
      p.failure("Password hash not found!")

elif hash_type == "SHA224":
  with log.progress("Attempting to break: {} hash [{}] using the {} file...\n".format(hash_type, wanted_hash, password_file)) as p:
    with open(password_file, "r", encoding='latin-1') as password_list: #encoding 
      for password in password_list:
        password = password.strip("\n").encode('latin-1') #stripping new line
        password_hash = sha224sumhex(password)
        p.status("[{}] {} == {}".format(attempts, password.decode('latin-1'), password_hash))
        if password_hash == wanted_hash:
          p.success("Password hash found after {} attempts. [{}] hashes to the {} hash of: {}".format(attempts, password.decode('latin-1'), hash_type, password_hash))
          exit()
        attempts += 1
      p.failure("Password hash not found!")
      
elif hash_type == "SHA256":
  with log.progress("Attempting to break: {} hash [{}] using the {} file...\n".format(hash_type, wanted_hash, password_file)) as p:
    with open(password_file, "r", encoding='latin-1') as password_list: #encoding 
      for password in password_list:
        password = password.strip("\n").encode('latin-1') #stripping new line
        password_hash = sha256sumhex(password)
        p.status("[{}] {} == {}".format(attempts, password.decode('latin-1'), password_hash))
        if password_hash == wanted_hash:
          p.success("Password hash found after {} attempts. [{}] hashes to the {} hash of: {}".format(attempts, password.decode('latin-1'), hash_type, password_hash))
          exit()
        attempts += 1
      p.failure("Password hash not found!")

elif hash_type == "SHA384":
  with log.progress("Attempting to break: {} hash [{}] using the {} file...\n".format(hash_type, wanted_hash, password_file)) as p:
    with open(password_file, "r", encoding='latin-1') as password_list: #encoding 
      for password in password_list:
        password = password.strip("\n").encode('latin-1') #stripping new line
        password_hash = sha384sumhex(password)
        p.status("[{}] {} == {}".format(attempts, password.decode('latin-1'), password_hash))
        if password_hash == wanted_hash:
          p.success("Password hash found after {} attempts. [{}] hashes to the {} hash of: {}".format(attempts, password.decode('latin-1'), hash_type, password_hash))
          exit()
        attempts += 1
      p.failure("Password hash not found!")
      
elif hash_type == "SHA512":
  with log.progress("Attempting to break: {} hash [{}] using the {} file...\n".format(hash_type, wanted_hash, password_file)) as p:
    with open(password_file, "r", encoding='latin-1') as password_list: #encoding 
      for password in password_list:
        password = password.strip("\n").encode('latin-1') #stripping new line
        password_hash = sha512sumhex(password)
        p.status("[{}] {} == {}".format(attempts, password.decode('latin-1'), password_hash))
        if password_hash == wanted_hash:
          p.success("Password hash found after {} attempts. [{}] hashes to the {} hash of: {}".format(attempts, password.decode('latin-1'), hash_type, password_hash))
          exit()
        attempts += 1
      p.failure("Password hash not found!")
      
