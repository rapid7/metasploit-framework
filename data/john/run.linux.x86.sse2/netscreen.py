##################################################################
#  Filename: netscreen.py
#
#  Please note this script will now run in Python version 3.x
#
# This script will generate a netscreen formatted password
#
# This program requires two command line arguments, and works in two modes:
#   Mode 1:
#    The first argument is a username
#    The second argument is a plaintext password
#   Mode 2:
#    The first argument is -f to indicate reading usernames and passwords from a file
#    The second argument is the filename to read
#
#  The input file should have one of the following formats (a "," or ":" separator):
#    <username>,<plain-text-password>
#    or
#    <username>:<plain-text-password>
#
#    (Don't put a "space" after the separator, unless it is part of the password)
#
#   Example input file:
#     admin,netscreen
#     cisco:cisco
#     robert,harris
#
# Output will be the username and hashed password in John the Ripper format
# If reading usernames and passwords from a file, the output file name will be: netscreen-JtR-output.txt
#      If the file netscreen-JtR-output.txt exists, it will be overwritten.
#
#  Version 2.04
#  Updated on September 13, 2010 by Robert B. Harris from VA and Brad Tilley
#     Updated to now run in Python v3.x (still works in Python 2.x)
#     Additional separator for the input file. It can now have the new separator ":" (or use the old one ",")
#     Now correctly handles a separator ("," or ":") in the password field when reading from a file.
#     Updated help text in script
#
#  Version 2.01
#  Updated on August 30, 2010 by Robert B. Harris from VA
#    Very minor changes, removed tab, noted it won't run in python 3.x
#
#  Version  2.0
#  Updated on August 12, 2010 by Robert B. Harris from VA
#    Updated to use the hashlib library
#    Updated to print help text if both input arguments are missing
#    Updated to optionally read from a file
#
##################################################################

import sys

def net(user, password):
  b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
  middle = "Administration Tools"
  s = "%s:%s:%s" % (user, middle, password)

   # For versions of Python 2.5 and older
  if sys.version_info[0] == 2 and sys.version_info[1] < 6:
    import md5
    m = md5.new(s).digest()
  else:
    import hashlib
    m = hashlib.md5(s.encode('latin_1')).digest()

  narray = []
  for i in range(8):
     if sys.version_info[0] == 2:
           n1 = ord(m[2*i])
           n2 = ord(m[2*i+1])
           narray.append( (n1<<8 & 0xff00) | (n2 & 0xff) )

     if sys.version_info[0] == 3:
           n1 = ord(chr(m[2*i]))
           n2 = ord(chr(m[2*i+1]))
           narray.append( (n1<<8 & 0xff00) | (n2 & 0xff) )
  res = ""
  for i in narray:
    p1 = i >> 12 & 0xf
    p2 = i >> 6  & 0x3f
    p3 = i       & 0x3f
    res = res + b64[p1] + b64[p2] + b64[p3]

  for c, n in  zip("nrcstn", [0, 6, 12, 17, 23, 29]):
        res = res[:n] + c + res[n:]
  return res


if __name__ == '__main__':
  if len(sys.argv) == 3:
    if  (sys.argv[1])== "-f":  # If true, reading from a file
       in_file = (sys.argv[2])   # 2nd commandline arg is the filename to read from
       input_file = open( in_file, 'r')
       output_file = open ("netscreen-JtR-output.txt" , 'w')
       import re
       for line in input_file:
          data=line.strip('\n')
          if re.search(',',line):
             data=data.split(',',1) # line contains ,
          else:
             if re.search(':',line):
               data=data.split(':',1) # line contains :
             else:
                 print ("\n\n\n")
                 print ("Error in input file.")
                 print ("The input file must have either a \",\" or \":\" separator on each line.")
                 print ("Also it should not contain any blank lines. Please correct the input file.")
                 break
          username = data[0]
          password = data[1]
          ciphertext = net(username,password)
          output_file.write ("%s:%s$%s" % (username,username,ciphertext))
          output_file.write ("\n")
       input_file.close()
       print("\nThe output file has been created.")
       output_file.close()
    else:   # We are not reading from a file
      username = sys.argv[1]
      password = sys.argv[2]
      ciphertext = net(username,password)
      print(("%s:%s$%s" % (username,username,ciphertext)))
  else:   # User did not input the required two commandline arguments
    print("\n\n")
    print("This program requires two commandline arguments:")
    print("The first argument is a username, or -f to indicate reading from a file.")
    print("The second argument is a plaintext password, or the name of the file to read from.")
    print("See the additional text at the beginning of this script for more details.\n")
    print("Output will be the username and the (Netscreen algorithm based) hashed password, in John the Ripper format. \n\n")
    print("Example")
    print("Input: netscreen.py admin netscreen")
    print("Output: admin:admin$nKv3LvrdAVtOcE5EcsGIpYBtniNbUn")
    print("(Netscreen uses the username as the salt)")
