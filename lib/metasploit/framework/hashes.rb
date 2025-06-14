module Metasploit
  module Framework
    # This module contains utilities for hashes, including one to identify them
    # Resource list:
    #  https://code.google.com/archive/p/hash-identifier/
    #  https://github.com/psypanda/hashID
    #  https://hashcat.net/wiki/doku.php?id=example_hashes
    #  http://pentestmonkey.net/cheat-sheet/john-the-ripper-hash-formats
    #  https://openwall.info/wiki/john/sample-hashes
    #  QNX formats -> https://moar.so/blog/qnx-password-hash-formats.html
    # rubocop:disable Metrics/ModuleLength
    module Hashes
      JTR_NTLMV1 = 'netntlm'.freeze
      JTR_NTLMV2 = 'netntlmv2'.freeze
      def self.identify_hash(hash)
        # @param [str] a string of a hashed password
        # @return [String] the jtr type or empty string on no match
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
          return 'bf' # bcrypt
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
        when hash.start_with?('$y$') && hash.split('$').last.length == 43
          return 'yescrypt'
        when hash.start_with?('_') && hash.length == 20
          return 'des,bsdi,crypt'
        when hash =~ %r{^[./\dA-Za-z]{13}$} # hash.length == 13
          return 'des,crypt'
        when hash =~ /^\$dynamic_82\$[\da-f]{128}\$HEX\$[\da-f]{32}$/ # jtr vmware ldap https://github.com/rapid7/metasploit-framework/pull/13865#issuecomment-660718108
          return 'dynamic_82'
        when hash.start_with?(/{SSHA}/i)
          return 'ssha'
        when hash.start_with?(/{SHA512}/i)
          return 'raw-sha512'
        when hash.start_with?(/{SHA256}/i)
          return 'raw-sha256'
        when hash.start_with?(/{SHA}/i)
          return 'raw-sha1'
        when hash.start_with?(/{MD5}/i)
          return 'raw-md5'
        when hash.start_with?(/{SMD5}/i)
          return 'smd5'
        when hash.start_with?(/{SSHA256}/i)
          return 'ssha256'
        when hash.start_with?(/{SSHA512}/i)
          return 'ssha512'
          # windows
        when hash.length == 65 && hash =~ /^[\da-fA-F]{32}:[\da-fA-F]{32}$/ && hash.split(':').first.upcase == 'AAD3B435B51404EEAAD3B435B51404EE'
          return 'nt'
        when hash.length == 65 && hash =~ /^[\da-fA-F]{32}:[\da-fA-F]{32}$/
          return 'lm'
        when hash =~ /^[^\\\/:*?"<>|]{1,20}[:]{2,3}([^\\\/:*?"<>|]{1,20})?:[a-f0-9]{48}:[a-f0-9]{48}:[a-f0-9]{16}$/
          return 'netntlm'
        when hash =~ /^([^\\\/:*?"<>|]{1,20}\\)?[^\\\/:*?"<>|]{1,20}[:]{2,3}([^\\\/:*?"<>|]{1,20}:)?[^\\\/:*?"<>|]{1,20}:[a-f0-9]{32}:[a-f0-9]+$/
          return 'netntlmv2'
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
        when hash.start_with?('{PKCS5S2}') && hash.length == 73
          return 'PBKDF2-HMAC-SHA1'
        when hash.start_with?('$B$') && hash.split('$').last.length == 32
          return 'mediawiki'
          # mobile
        when hash =~ /^[A-F0-9]{40}:[a-f0-9]{16}$/
          return 'android-sha1'
        when hash =~ /^[A-F0-9]{32}:[a-f0-9]{16}$/
          return 'android-md5'
          # other
        when hash =~ /^<\d+@.+?>#\w{32}$/
          return 'hmac-md5'
        when hash.length == 114 && hash.start_with?('$M$')
          return 'F5-Secure-Vault'
        when hash =~ /^M\$[[:print:]]+#[\da-fA-F]{32}(?:(?::[[:print:]]*$)|$)/
          return 'mscash'
        when hash =~ /^\$DCC2\$\d+#[[:print:]]+#[\da-fA-F]{32}(?:(?::[[:print:]]*$)|$)/
          return 'mscash2'
        when hash =~ /^\*?[\da-fA-F]{32}\*[\da-fA-F]{32}$/
          # we accept the beginning star as optional
          return 'vnc'
        when hash =~ /^\$pbkdf2-sha256\$[0-9]+\$[a-z0-9\/.]+\$[a-z0-9\/.]{43}$/i
          return 'pbkdf2-sha256'
        when hash =~ /^\$sntp-ms\$[\da-fA-F]{32}\$[\da-fA-F]{96}$/
          return 'timeroast'
        when hash =~ /^\$krb5tgs\$23\$\*.+\$[\da-fA-F]{32}\$[\da-fA-F]+$/
          return 'krb5tgs-rc4'
        when hash =~ /^\$krb5tgs\$18\$.+\$[\da-fA-F]{24}\$[\da-fA-F]+$/
          return 'krb5tgs-aes256'
        when hash =~ /^\$krb5tgs\$17\$.+\$[\da-fA-F]{24}\$[\da-fA-F]+$/
          return 'krb5tgs-aes128'
        when hash =~ /^\$krb5asrep\$23\$[^:]+:[\da-fA-F]{32}\$[\da-fA-F]+$/
          return 'krb5asrep-rc4'
        end
        ''
      end
      # rubocop:enable Metrics/ModuleLength
    end
  end
end
