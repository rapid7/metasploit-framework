# This method takes a {str}, and attempt to determine what type
# of hash it is, and returns a cred:jtr formatted string.
#
# @param [str] a string of a hashed password
# @return [String] the jtr type or empty string on no match

# Resource list:
#  https://code.google.com/archive/p/hash-identifier/
#  https://hashcat.net/wiki/doku.php?id=example_hashes
#  http://pentestmonkey.net/cheat-sheet/john-the-ripper-hash-formats
#  https://openwall.info/wiki/john/sample-hashes
#  QNX formats -> https://moar.so/blog/qnx-password-hash-formats.html

def identify_hash(hash)
  hash = hash.strip
  case
    when hash.start_with?('$1$')
      return 'md5'
    when hash.start_with?('$2a$'), hash.start_with?('$2y$')
      return 'bf' #bcrypt
    when hash.start_with?('$5$')
      return 'sha256,crypt'
    when hash.start_with?('$6$')
      return 'sha512,crypt'
    when hash.start_with?('@S@')
      return 'qnx,sha512'
    when hash.start_with?('@s@')
      return 'qnx,sha256'
    when hash.start_with?('@m@')
      return 'qnx,md5'
    when hash.start_with?('_')
      return 'des,bsdi,crypt'
  end
  return''
end
