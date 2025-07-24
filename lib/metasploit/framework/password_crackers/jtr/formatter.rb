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
            params_to_jtr(
              (cred.public.nil? ? '' : cred.public.username),
              cred.private.data,
              cred.class.model_name.element.to_sym,
              format: cred.private.jtr_format,
              db_id: cred.id
            )
          end

          def self.params_to_jtr(username, private_data, private_type, format: nil, db_id: nil)
            case private_type
            when :ntlm_hash
              return "#{username}:#{db_id}:#{private_data}:::#{db_id}"
            when :postgres_md5
              if format =~ /postgres|raw-md5/
                # john --list=subformats | grep 'PostgreSQL MD5'
                # UserFormat = dynamic_1034  type = dynamic_1034: md5($p.$u) (PostgreSQL MD5)
                hash_string = private_data
                hash_string.gsub!(/^md5/, '')
                return "#{username}:$dynamic_1034$#{hash_string}:#{db_id}:"
              end
            when :nonreplayable_hash
              case format
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
                if private_data =~ /S:([\dA-F]{60})/ # oracle 11
                  return "#{username}:#{Regexp.last_match(1)}:#{db_id}:"
                end
              when /oracle12c/
                if private_data =~ /T:([\dA-F]{160})/ # oracle 12c
                  return "#{username}:$oracle12c$#{Regexp.last_match(1).downcase}:#{db_id}:"
                end
              when /dynamic_1506/
                if private_data =~ /H:([\dA-F]{32})/ # oracle 11
                  return "#{username.upcase}:$dynamic_1506$#{Regexp.last_match(1)}:#{db_id}:"
                end
              when /oracle/ # oracle
                if format.start_with?('des') # 'des,oracle', not oracle11/12c
                  return "#{username}:O$#{username}##{private_data}:#{db_id}:"
                end
              when /md5|des|bsdi|crypt|bf|sha256|sha512|xsha512/
                # md5(crypt), des(crypt), b(crypt), sha256(crypt), sha512(crypt), xsha512
                return "#{username}:#{private_data}:::::#{db_id}:"
              when /xsha/
                # xsha512
                return "#{username}:#{private_data.upcase}:::::#{db_id}:"
              when /netntlm/
                return "#{private_data}::::::#{db_id}:"
              when /qnx/
                # https://moar.so/blog/qnx-password-hash-formats.html
                hash = private_data.end_with?(':0:0') ? private_data : "#{private_data}:0:0"
                return "#{username}:#{hash}"
              when /Raw-MD5u/
                # This is just md5(unicode($p)), where $p is the password.
                # Avira uses to store their passwords, there may be other apps that also use this though.
                # The trailing : shows an empty salt. This is because hashcat only has one unicode hash
                # format which is compatible, type 30, but that is listed as md5(utf16le($pass).$salt)
                # with a sample hash of b31d032cfdcf47a399990a71e43c5d2a:144816. So this just outputs
                # The hash as *hash*: so that it is both JTR and hashcat compatible
                return "#{private_data}:"
              when /vnc/
                # add a beginning * if one is missing
                return "$vnc$#{private_data.start_with?('*') ? private_data.upcase : "*#{private_data.upcase}"}"
              when /^(krb5.|timeroast$)/
                return private_data
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

                return "#{username}:#{private_data}:#{db_id}:"
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
