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
  hash = hash.to_s.strip
  case
    # operating systems
    when hash.start_with?('$1$') && hash.length == 34
      return 'md5'
    when hash.start_with?('$2$') && hash.length == 59,
         hash.start_with?('$2a$') && hash.length == 60,
         hash.start_with?('$2b$') && hash.length == 60,
         hash.start_with?('$2x$') && hash.length == 60,
         hash.start_with?('$2y$') && hash.length == 60
      return 'bf' #bcrypt
    when hash.start_with?('$5$') && hash.split('$').last.length == 43
      # we dont check full length since it may have 'rounds=' in the [1] area or not with an arbitrary length number
      return 'sha256,crypt'
    when hash.start_with?('$6$') && hash.split('$').last.length == 86
      # we dont check full length since it may have 'rounds=' in the [1] area or not with an arbitrary length number
      return 'sha512,crypt'
    when hash.start_with?('@S@') && hash.length == 148
      return 'qnx,sha512'
    when hash.start_with?('@s@') && hash.length == 84
      return 'qnx,sha256'
    when hash.start_with?('@m@') && hash.length == 52
      return 'qnx,md5'
    when hash.start_with?('_') && hash.length == 20
      return 'des,bsdi,crypt'
    when hash =~ /^[\.\/\dA-Za-z]{13}$/ # hash.length == 13
      return 'des,crypt'
    # windows
    when hash.length == 65 && hash =~ /^[\da-fA-F]{32}:[\da-fA-F]{32}$/ && hash.split(':').first.upcase == 'AAD3B435B51404EEAAD3B435B51404EE'
      return 'nt'
    when hash.length == 65 && hash =~ /^[\da-fA-F]{32}:[\da-fA-F]{32}$/
      return 'lm'
    # OSX
    when hash.start_with?('$ml$') && hash.split('$').last.length == 256
      return 'pbkdf2-hmac-sha512,osx' # 10.8+
    when hash =~ /^[\da-fA-F]{48}$/ # hash.length == 48
      return 'xsha,osx' # 10.4-10.6
    # databases
    when hash.start_with?('0x0100') && hash.length == 54
      return 'mssql05'
    when hash.start_with?('0x0100') && hash.length == 94
      return 'mssql'
    when hash.start_with?('0x0200') && hash.length == 142
      return 'mssql12'
    when hash =~ /^[\da-f]{16}$/ # hash.length == 16
      return 'mysql' # mysql323 (pre 4.1)
    when hash.start_with?('*') && hash.length == 41
      return 'mysql-sha1' # mysql 4.1+
    when hash.start_with?('md5') && hash.length == 35
      return 'postgres'
    when hash =~ /^[\da-fA-F]{16}$/
      return 'des,oracle' # pre 11g
    when hash =~ /^S:[\dA-F]{60}$/
      return 'raw-sha1,oracle11'
    when hash =~ /^S:[\dA-F]{60};H:[\dA-F]{32};T:[\dA-F]{160}$/
      return 'raw-sha1,oracle'
    when hash =~ /^H:[\dA-F]{32};T:[\dA-F]{160}$/
      return 'pbkdf2,oracle12c'
    # webapps
    when hash.start_with?('$P$') && hash.length == 34,
         hash.start_with?('$H$') && hash.length == 34
      return 'phpass' # wordpress, drupal, phpbb3 (H not P)
    when hash.start_with?('$ml$') && hash.length == 203
      return 'PBKDF2-HMAC-SHA512'
  end
  ''
end
