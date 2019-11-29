# This method takes a {framework.db.cred}, and normalizes it
# to the string format JTR is expecting.
#
# @param [credClass] a credential from framework.db
# @return [String] the hash in jtr format or nil on no mach
def hash_to_jtr(cred)
  case cred.private.type
  when 'Metasploit::Credential::NTLMHash'
    return "#{cred.public.username}:#{cred.id}:#{cred.private.data}:::#{cred.id}"
  when 'Metasploit::Credential::PostgresMD5'
    if cred.private.jtr_format =~ /postgres|raw-md5/
      # john --list=subformats | grep 'PostgreSQL MD5'
      #UserFormat = dynamic_1034  type = dynamic_1034: md5($p.$u) (PostgreSQL MD5)
      hash_string = cred.private.data
      hash_string.gsub!(/^md5/, '')
      return "#{cred.public.username}:$dynamic_1034$#{hash_string}"
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
    when /raw-sha1|oracle11/ # oracle 11
      if cred.private.data =~ /S:([\dA-F]{60})/ # oracle 11
        return "#{cred.public.username}:#{$1}:#{cred.id}:"
      end
    when /oracle12c/
      if cred.private.data =~ /T:([\dA-F]{160})/ # oracle 12c
        return "#{cred.public.username}:$oracle12c$#{$1.downcase}:#{cred.id}:"
      end
    when /dynamic_1506/
      if cred.private.data =~ /H:([\dA-F]{32})/ # oracle 11
        return "#{cred.public.username.upcase}:$dynamic_1506$#{$1}:#{cred.id}:"
      end
    when /oracle/ # oracle
      if cred.private.jtr_format.start_with?('des') # 'des,oracle', not oracle11/12c
        return "#{cred.public.username}:O$#{cred.public.username}##{cred.private.data}:#{cred.id}:"
      end
    when /md5|des|bsdi|crypt|bf|sha256|sha512|xsha512/
      # md5(crypt), des(crypt), b(crypt), sha256(crypt), sha512(crypt), xsha512
      return "#{cred.public.username}:#{cred.private.data}:::::#{cred.id}:"
    when /qnx/
      # https://moar.so/blog/qnx-password-hash-formats.html
      hash = cred.private.data.end_with?(':0:0') ? cred.private.data : "#{cred.private.data}:0:0"
      return "#{cred.public.username}:#{hash}"
    else
      # /mysql|mysql-sha1/
      # /mssql|mssql05|mssql12/
      # /des(crypt)/
      # /mediawiki|phpass|atlassian/
      return "#{cred.public.username}:#{cred.private.data}:#{cred.id}:"
    end
  end
  nil
end
