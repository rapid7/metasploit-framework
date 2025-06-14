module Metasploit
  module Framework
    module PasswordCracker
      module JtR
        module Formatter
          # This method takes a {framework.db.cred}, and normalizes it
          # to the string format JTR is expecting.
          #
          # @param cred [credClass] A credential from framework.db
          # @return [String] The hash in jtr format or nil on no match.
          def self.hash_to_jtr(cred)
            case cred.private.type
            when 'Metasploit::Credential::NTLMHash'
              return "#{cred.public.username}:#{cred.id}:#{cred.private.data}:::#{cred.id}"
            when 'Metasploit::Credential::PostgresMD5'
              if cred.private.jtr_format =~ /postgres|raw-md5/
                # john --list=subformats | grep 'PostgreSQL MD5'
                # UserFormat = dynamic_1034  type = dynamic_1034: md5($p.$u) (PostgreSQL MD5)
                hash_string = cred.private.data
                hash_string.gsub!(/^md5/, '')
                return "#{cred.public.username}:$dynamic_1034$#{hash_string}:#{cred.id}:"
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
                  return "#{cred.public.username}:#{Regexp.last_match(1)}:#{cred.id}:"
                end
              when /oracle12c/
                if cred.private.data =~ /T:([\dA-F]{160})/ # oracle 12c
                  return "#{cred.public.username}:$oracle12c$#{Regexp.last_match(1).downcase}:#{cred.id}:"
                end
              when /dynamic_1506/
                if cred.private.data =~ /H:([\dA-F]{32})/ # oracle 11
                  return "#{cred.public.username.upcase}:$dynamic_1506$#{Regexp.last_match(1)}:#{cred.id}:"
                end
              when /oracle/ # oracle
                if cred.private.jtr_format.start_with?('des') # 'des,oracle', not oracle11/12c
                  return "#{cred.public.username}:O$#{cred.public.username}##{cred.private.data}:#{cred.id}:"
                end
              when /md5|des|bsdi|crypt|bf|sha256|sha512|xsha512/
                # md5(crypt), des(crypt), b(crypt), sha256(crypt), sha512(crypt), xsha512
                return "#{cred.public.username}:#{cred.private.data}:::::#{cred.id}:"
              when /xsha/
                # xsha512
                return "#{cred.public.username}:#{cred.private.data.upcase}:::::#{cred.id}:"
              when /netntlm/
                return "#{cred.private.data}::::::#{cred.id}:"
              when /qnx/
                # https://moar.so/blog/qnx-password-hash-formats.html
                hash = cred.private.data.end_with?(':0:0') ? cred.private.data : "#{cred.private.data}:0:0"
                return "#{cred.public.username}:#{hash}"
              when /Raw-MD5u/
                # This is just md5(unicode($p)), where $p is the password.
                # Avira uses to store their passwords, there may be other apps that also use this though.
                # The trailing : shows an empty salt. This is because hashcat only has one unicode hash
                # format which is compatible, type 30, but that is listed as md5(utf16le($pass).$salt)
                # with a sample hash of b31d032cfdcf47a399990a71e43c5d2a:144816. So this just outputs
                # The hash as *hash*: so that it is both JTR and hashcat compatible
                return "#{cred.private.data}:"
              when /vnc/
                # add a beginning * if one is missing
                return "$vnc$#{cred.private.data.start_with?('*') ? cred.private.data.upcase : "*#{cred.private.data.upcase}"}"
              when /^(krb5.|timeroast$)/
                return cred.private.data
              else
                # /mysql|mysql-sha1/
                # /mssql|mssql05|mssql12/
                # /des(crypt)/
                # /mediawiki|phpass|atlassian/
                # /dynamic_82/
                # /ssha/
                # /raw-sha512/
                # /raw-sha256/
                # /xsha/
                # /mscash2/
                # This also handles *other* type credentials which aren't guaranteed to have a public

                return "#{cred.public.nil? ? ' ' : cred.public.username}:#{cred.private.data}:#{cred.id}:"
              end
            end
            nil
          end

          # This method takes a {framework.db.cred}, and normalizes it
          # from the JTR format to the DB format.
          #
          # @param [credClass] a credential from framework.db
          # @return [Array] All of the hash types that may be in the DB that apply
          def self.jtr_to_db(cred_type)
            case cred_type
            when 'descrypt' # from aix module
              return ['des']
            when 'oracle' # from databases module
              return ['des,oracle']
            when 'dynamic_1506'
              return ['dynamic_1506']
            when 'oracle11'
              return ['raw-sha1,oracle']
            when 'oracle12c'
              return ['pbkdf2,oracle12c']
            when 'dynamic_1034'
              return ['raw-md5,postgres']
            when 'md5crypt' # from linux module
              return ['md5']
            when 'descrypt'
              return ['des']
            when 'bsdicrypt'
              return ['bsdi']
            when 'sha256crypt'
              return ['sha256,crypt']
            when 'sha512crypt'
              return ['sha512,crypt']
            when 'bcrypt'
              return ['bf']
            end
            return [cred_type]
          end
        end
      end
    end
  end
end
