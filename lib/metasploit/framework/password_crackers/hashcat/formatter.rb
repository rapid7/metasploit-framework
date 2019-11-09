# This method takes a {framework.db.cred}, and normalizes it
# to the string format hashcat is expecting.
# https://hashcat.net/wiki/doku.php?id=example_hashes
#
# @param [credClass] a credential from framework.db
# @return [String] the hash in jtr format or nil on no mach
def hash_to_hashcat(cred)
  case cred.private.type
  when 'Metasploit::Credential::NTLMHash'
    both = cred.private.data.split(":")
    if both[0].upcase == 'AAD3B435B51404EEAAD3B435B51404EE' #lanman empty, return ntlm
      return both[1] # ntlm hash-mode: 1000
    end
    return both[0] #give lanman, hash-mode: 3000
  when 'Metasploit::Credential::PostgresMD5' #hash-mode: 12
    if cred.private.jtr_format =~ /postgres|raw-md5/
      hash_string = cred.private.data
      hash_string.gsub!(/^md5/, '')
      return "#{hash_string}:#{cred.public.username}"
    end
  when 'Metasploit::Credential::NonreplayableHash'
    case cred.private.jtr_format
      # oracle 11+ password hash descriptions:
      # this password is stored as a long ascii string with several sections
      # https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/changes-in-oracle-database-12c-password-hashes/
      # example:
      # hash = []
      # hash << "S:8F2D65FB5547B71C8DA3760F10960428CD307B1C6271691FC55C1F56554A;"
      # hash << "H:DC9894A01797D91D92ECA1DA66242209;"
      # hash << "T:23D1F8CAC9001F69630ED2DD8DF67DD3BE5C470B5EA97B622F757FE102D8BF14BEDC94A3CC046D10858D885DB656DC0CBF899A79CD8C76B788744844CADE54EEEB4FDEC478FB7C7CBFBBAC57BA3EF22C"
      # puts hash.join('')
      # S: = 60 characters -> sha1(password + salt (10 bytes))
      #         40 char sha1, 20 char salt
      #         hash is 8F2D65FB5547B71C8DA3760F10960428CD307B1C
      #         salt is 6271691FC55C1F56554A
      # H: = 32 characters
      #         legacy MD5
      # T: = 160 characters
      #         PBKDF2-based SHA512 hash specific to 12C (12.1.0.2+)
    when /raw-sha1|oracle11/ # oracle 11, hash-mode: 112
      if cred.private.data =~ /S:([\dA-F]{60})/ # oracle 11
        # hashcat wants a 40 character string, : 20 character string
        return $1.scan(/.{1,40}/m).join(':').downcase
      end
    when /oracle12c/
      if cred.private.data =~ /T:([\dA-F]{160})/ # oracle 12c, hash-mode: 12300
        return $1.upcase
      end
    when /dynamic_1506|postgres/
      #this may not be correct
      if cred.private.data =~ /H:([\dA-F]{32})/ # oracle 11, hash-mode: 3100
        return "#{$1}:#{cred.public.username}"
      end
    when /oracle/ # oracle
      if cred.private.jtr_format.start_with?('des') # 'des,oracle', not oracle11/12c, hash-mode: 3100
        return "#{cred.private.data}"
      end
    when /mysql-sha1/
      # lowercase, and remove the first character if its a *
      return cred.private.data.downcase.sub('*','')
    when /md5|des|bsdi|crypt|bf/, /mssql|mssql05|mssql12|mysql/, /sha256|sha-256/,
         /sha512|sha-512/, /xsha|xsha512|PBKDF2-HMAC-SHA512/,
         /mediawiki|phpass|PBKDF2-HMAC-SHA1/,
         /android-sha1/
      #            md5(crypt), des(crypt), b(crypt), sha256, sha512, xsha, xsha512, PBKDF2-HMAC-SHA512
      # hash-mode: 500          1500        3200      7400    1800   122   1722       7100
      #            mssql, mssql05, mssql12, mysql, mysql-sha1
      # hash-mode: 131,    132,     1731    200        300
      #            mediawiki, phpass, PBKDF2-HMAC-SHA1
      # hash-mode: 3711,      400,    12001
      #            android-sha1
      # hash-mode: 5800
      return cred.private.data
    end
  end
  nil
end


