module Metasploit
  module Framework
    module PasswordCracker
      module Hashcat
        module Formatter
          # This method takes a {framework.db.cred}, and normalizes it
          # to the string format hashcat is expecting.
          # https://hashcat.net/wiki/doku.php?id=example_hashes
          #
          # @param cred [credClass] A credential from framework.db
          # @return [String] The hash in jtr format or nil on no match.
          def self.hash_to_hashcat(cred)
            case cred.private.type
            when 'Metasploit::Credential::NTLMHash'
              both = cred.private.data.split(':')
              if both[0].upcase == 'AAD3B435B51404EEAAD3B435B51404EE' # lanman empty, return ntlm
                return "#{cred.id}:#{both[1]}" # ntlm hash-mode: 1000
              end

              return "#{cred.id}:#{both[0]}" # give lanman, hash-mode: 3000
            when 'Metasploit::Credential::PostgresMD5' # hash-mode: 12
              if cred.private.jtr_format =~ /postgres|raw-md5/
                hash_string = cred.private.data
                hash_string.gsub!(/^md5/, '')
                return "#{cred.id}:#{hash_string}:#{cred.public.username}"
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
              when /^pbkdf2-sha256/
                # hashmode: 10900
                # from: $pbkdf2-sha256$260000$Q1hzYjU5dFNMWm05QUJCTg$s.vmjGlIV0ZKV1Sp3dTdrcn/i9CTqxPZ0klve4HreeU
                # to:   sha256:29000:Q1hzYjU5dFNMWm05QUJCTg==:s+vmjGlIV0ZKV1Sp3dTdrcn/i9CTqxPZ0klve4HreeU=

                # https://hashcat.net/forum/thread-7854-post-42417.html#pid42417 ironically gives Token encoding exception
                c = cred.private.data.sub('$pbkdf2-sha256', 'sha256').split('$')

                # This method takes a string which is likely base64 encoded
                # however, there is an arbitrary amount of = missing from the end
                # so we attempt to add = until we are able to decode it
                #
                # @param str [String] the base64-ish string
                # @return [String] the corrected string
                def add_equals_to_base64(str)
                  ['', '=', '=='].each do |equals|
                    to_test = "#{str}#{equals}"
                    Base64.strict_decode64(to_test)
                    return to_test
                  rescue ArgumentError
                    next
                  end
                  nil
                end

                c[2] = add_equals_to_base64(c[2].gsub('.', '+')) # pad back out
                c[3] = add_equals_to_base64(c[3].gsub('.', '+')) # pad back out
                return c.join(':')
              when /hmac-md5/
                data = cred.private.data.split('#')
                password = Rex::Text.encode_base64("#{cred.public.username} #{data[1]}")
                return "#{cred.id}:$cram_md5$#{Rex::Text.encode_base64(data[0])}$#{password}"
              when /raw-sha1|oracle11/ # oracle 11, hash-mode: 112
                if cred.private.data =~ /S:([\dA-F]{60})/ # oracle 11
                  # hashcat wants a 40 character string, : 20 character string
                  return "#{cred.id}:#{Regexp.last_match(1).scan(/.{1,40}/m).join(':').downcase}"
                end
              when /oracle12c/
                if cred.private.data =~ /T:([\dA-F]{160})/ # oracle 12c, hash-mode: 12300
                  return "#{cred.id}:#{Regexp.last_match(1).upcase}"
                end
              when /dynamic_1506|postgres/
                # this may not be correct
                if cred.private.data =~ /H:([\dA-F]{32})/ # oracle 11, hash-mode: 3100
                  return "#{cred.id}:#{Regexp.last_match(1)}:#{cred.public.username}"
                end
              when /oracle/ # oracle
                if cred.private.jtr_format.start_with?('des') # 'des,oracle', not oracle11/12c, hash-mode: 3100
                  return "#{cred.id}:#{cred.private.data}"
                end
              when /dynamic_82/
                return "#{cred.id}:#{cred.private.data.sub('$HEX$', ':').sub('$dynamic_82$', '')}"
              when /mysql-sha1/
                # lowercase, and remove the first character if its a *
                return "#{cred.id}:#{cred.private.data.downcase.sub('*', '')}"
              when /md5|des|bsdi|crypt|bf/, /mssql|mssql05|mssql12|mysql/, /sha256|sha-256/,
                  /sha512|sha-512/, /xsha|xsha512|PBKDF2-HMAC-SHA512/,
                  /mediawiki|phpass|PBKDF2-HMAC-SHA1/,
                  /android-sha1/, /android-samsung-sha1/, /android-md5/,
                  /ssha/, /raw-sha512/, /raw-sha256/
                #            md5(crypt), des(crypt), b(crypt), sha256, sha512, xsha, xsha512, PBKDF2-HMAC-SHA512
                # hash-mode: 500         1500        3200      7400    1800    122   1722     7100
                #            mssql, mssql05, mssql12, mysql, mysql-sha1
                # hash-mode: 131,   132,     1731    200     300
                #            mediawiki, phpass, PBKDF2-HMAC-SHA1
                # hash-mode: 3711,      400,    12001
                #            android-sha1
                # hash-mode: 5800
                #            ssha, raw-sha512, raw-sha256
                # hash-mode: 111,  1700,       1400
                return "#{cred.id}:#{cred.private.data}"
              when /^mscash$/
                # hash-mode: 1100
                data = cred.private.data.split(':').first
                if /^M\$(?<salt>[[:print:]]+)#(?<hash>[\da-fA-F]{32})/ =~ data
                  return "#{cred.id}:#{hash}:#{salt}"
                end
              when /^mscash2$/
                # hash-mode: 2100
                return "#{cred.id}:#{cred.private.data.split(':').first}"
              when /netntlm(v2)?/
                #            netntlm, netntlmv2
                # hash-mode: 5500     5600
                return "#{cred.id}:#{cred.private.data}"
              when /^vnc$/
                # https://hashcat.net/forum/thread-8833.html
                # while we can do the transformation, we'd have to throw extra flags at hashcat which aren't currently written into the lib for automation
                nil
              when /^krb5$/
                return "#{cred.id}:#{cred.private.data}"
              when /^(krb5.|timeroast$)/
                return cred.private.data
              end
            end
            nil
          end
        end
      end
    end
  end
end
