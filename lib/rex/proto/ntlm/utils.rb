# -*- coding: binary -*-
require 'rex/proto/ntlm/constants'
require 'rex/proto/ntlm/crypt'
require 'rex/proto/ntlm/exceptions'

module Rex::Proto::NTLM
  class Utils

    # duplicate from lib/rex/proto/smb/utils cause we only need this fonction from Rex::Proto::SMB::Utils
    # Convert a unix timestamp to a 64-bit signed server time
    def self.time_unix_to_smb(unix_time)
      t64 = (unix_time + 11644473600) * 10000000
      thi = (t64 & 0xffffffff00000000) >> 32
      tlo = (t64 & 0x00000000ffffffff)
      return [thi, tlo]
    end

    # Determine whether the password is a known hash format
    def self.is_pass_ntlm_hash?(str)
      str.downcase =~ /^[0-9a-f]{32}:[0-9a-f]{32}$/
    end

    #
    # Prepends an ASN1 formatted length field to a piece of data
    #
    def self.asn1encode(str = '')
      res = ''

      # If the high bit of the first byte is 1, it contains the number of
      # length bytes that follow

      case str.length
        when 0 .. 0x7F
          res = [str.length].pack('C') + str
        when 0x80 .. 0xFF
          res = [0x81, str.length].pack('CC') + str
        when 0x100 .. 0xFFFF
          res = [0x82, str.length].pack('Cn') + str
        when  0x10000 .. 0xffffff
          res = [0x83, str.length >> 16, str.length & 0xFFFF].pack('CCn') + str
        when  0x1000000 .. 0xffffffff
          res = [0x84, str.length].pack('CN') + str
        else
          raise "ASN1 str too long"
      end
      return res
    end

    # GSS functions

    # GSS BLOB usefull for SMB_NEGOCIATE_RESPONSE message
    # mechTypes: 2 items :
    # 	-MechType: 1.3.6.1.4.1.311.2.2.30 (SNMPv2-SMI::enterprises.311.2.2.30)
    # 	-MechType: 1.3.6.1.4.1.311.2.2.10 (NTLMSSP - Microsoft NTLM Security Support Provider)
    #
    # this is the default on Win7
    def self.make_simple_negotiate_secblob_resp
      blob =
      "\x60" + self.asn1encode(
        "\x06" + self.asn1encode(
          "\x2b\x06\x01\x05\x05\x02"
        ) +
        "\xa0" + self.asn1encode(
          "\x30" + self.asn1encode(
            "\xa0" + self.asn1encode(
              "\x30" + self.asn1encode(
                "\x06" + self.asn1encode(
                  "\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a"
                )
              )
            )
          )
        )
      )

      return blob
    end

    # GSS BLOB usefull for SMB_NEGOCIATE_RESPONSE message
    # mechTypes: 4 items :
    # 	MechType: 1.2.840.48018.1.2.2 (MS KRB5 - Microsoft Kerberos 5)
    # 	MechType: 1.2.840.113554.1.2.2 (KRB5 - Kerberos 5)
    # 	MechType: 1.2.840.113554.1.2.2.3 (KRB5 - Kerberos 5 - User to User)
    # 	MechType: 1.3.6.1.4.1.311.2.2.10 (NTLMSSP - Microsoft NTLM Security Support Provider)
    # mechListMIC:
    # 	principal: account@domain
    def self.make_negotiate_secblob_resp(account, domain)
      blob =
      "\x60" + self.asn1encode(
        "\x06" + self.asn1encode(
          "\x2b\x06\x01\x05\x05\x02"
        ) +
        "\xa0" + self.asn1encode(
          "\x30" + self.asn1encode(
            "\xa0" + self.asn1encode(
              "\x30" + self.asn1encode(
                "\x06" + self.asn1encode(
                  "\x2a\x86\x48\x82\xf7\x12\x01\x02\x02"
                ) +
                "\x06" + self.asn1encode(
                  "\x2a\x86\x48\x86\xf7\x12\x01\x02\x02"
                ) +
                "\x06" + self.asn1encode(
                  "\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x03"
                ) +
                "\x06" + self.asn1encode(
                  "\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a"
                )
              )
            ) +
            "\xa3" + self.asn1encode(
              "\x30" + self.asn1encode(
                "\xa0" + self.asn1encode(
                  "\x1b" + self.asn1encode(
                    account + '@' + domain
                  )
                )
              )
            )
          )
        )
      )

      return blob
    end

    # BLOB without GSS usefull for ntlmssp type 1 message
    def self.make_ntlmssp_blob_init(domain = 'WORKGROUP', name = 'WORKSTATION', flags=0x80201)
      blob =	"NTLMSSP\x00" +
        [1, flags].pack('VV') +

        [
          domain.length,  #length
          domain.length,  #max length
          32
        ].pack('vvV') +

        [
          name.length,	#length
          name.length, 	#max length
          domain.length + 32
        ].pack('vvV') +

        domain + name
      return blob
    end

    # GSS BLOB usefull for ntlmssp type 1 message
    def self.make_ntlmssp_secblob_init(domain = 'WORKGROUP', name = 'WORKSTATION', flags=0x80201)
      blob =
      "\x60" + self.asn1encode(
        "\x06" + self.asn1encode(
          "\x2b\x06\x01\x05\x05\x02"
        ) +
        "\xa0" + self.asn1encode(
          "\x30" + self.asn1encode(
            "\xa0" + self.asn1encode(
              "\x30" + self.asn1encode(
                "\x06" + self.asn1encode(
                  "\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a"
                )
              )
            ) +
            "\xa2" + self.asn1encode(
              "\x04" + self.asn1encode(
                make_ntlmssp_blob_init(domain, name, flags)
              )
            )
          )
        )
      )

      return blob
    end


    # BLOB without GSS usefull for ntlm type 2 message
    def self.make_ntlmssp_blob_chall(win_domain, win_name, dns_domain, dns_name, chall, flags)

      addr_list  = ''
      addr_list  << [2, win_domain.length].pack('vv') + win_domain
      addr_list  << [1, win_name.length].pack('vv') + win_name
      addr_list  << [4, dns_domain.length].pack('vv') + dns_domain
      addr_list  << [3, dns_name.length].pack('vv') + dns_name
      addr_list  << [0, 0].pack('vv')

      ptr  = 0
      blob =	"NTLMSSP\x00" +
          [2].pack('V') +
          [
            win_domain.length,  # length
            win_domain.length,  # max length
            (ptr += 48) # offset
          ].pack('vvV') +
          [ flags ].pack('V') +
          chall +
          "\x00\x00\x00\x00\x00\x00\x00\x00" +
          [
            addr_list.length,  # length
            addr_list.length,  # max length
            (ptr += win_domain.length)
          ].pack('vvV') +
          win_domain +
          addr_list
      return blob
    end

    # GSS BLOB usefull for ntlmssp type 2 message
    def self.make_ntlmssp_secblob_chall(win_domain, win_name, dns_domain, dns_name, chall, flags)

      blob =
        "\xa1" + self.asn1encode(
          "\x30" + self.asn1encode(
            "\xa0" + self.asn1encode(
              "\x0a" + self.asn1encode(
                "\x01"
              )
            ) +
            "\xa1" + self.asn1encode(
              "\x06" + self.asn1encode(
                "\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a"
              )
            ) +
            "\xa2" + self.asn1encode(
              "\x04" + self.asn1encode(
                make_ntlmssp_blob_chall(win_domain, win_name, dns_domain, dns_name, chall, flags)
              )
            )
          )
        )

      return blob
    end

    # BLOB without GSS Usefull for ntlmssp type 3 message
    def self.make_ntlmssp_blob_auth(domain, name, user, lm, ntlm, enc_session_key, flags = 0x080201)
      lm ||= "\x00" * 24
      ntlm ||= "\x00" * 24

      domain_uni = Rex::Text.to_unicode(domain)
      user_uni   = Rex::Text.to_unicode(user)
      name_uni   = Rex::Text.to_unicode(name)
      session    = enc_session_key

      ptr  = 64

      blob = "NTLMSSP\x00" +
        [ 3 ].pack('V') +

        [	# Lan Manager Response
          lm.length,
          lm.length,
          (ptr)
        ].pack('vvV') +

        [	# NTLM Manager Response
          ntlm.length,
          ntlm.length,
          (ptr += lm.length)
        ].pack('vvV') +

        [	# Domain Name
          domain_uni.length,
          domain_uni.length,
          (ptr += ntlm.length)
        ].pack('vvV') +

        [	# Username
          user_uni.length,
          user_uni.length,
          (ptr += domain_uni.length)
        ].pack('vvV') +

        [	# Hostname
          name_uni.length,
          name_uni.length,
          (ptr += user_uni.length)
        ].pack('vvV') +

        [	# Session Key (none)
          session.length,
          session.length,
          (ptr += name_uni.length)
        ].pack('vvV') +

        [ flags ].pack('V') +

        lm +
        ntlm +
        domain_uni +
        user_uni +
        name_uni +
        session + "\x00"
      return blob

    end

    # GSS BLOB Usefull for ntlmssp type 3 message
    def self.make_ntlmssp_secblob_auth(domain, name, user, lm, ntlm, enc_session_key, flags = 0x080201)

      blob =
        "\xa1" + self.asn1encode(
          "\x30" + self.asn1encode(
            "\xa2" + self.asn1encode(
              "\x04" + self.asn1encode(
              make_ntlmssp_blob_auth(domain, name, user, lm, ntlm, enc_session_key, flags )
            )
          )
        )
      )
      return blob
    end


    # GSS BLOB Usefull for SMB Success
    def self.make_ntlmv2_secblob_success
      blob =
        "\xa1" + self.asn1encode(
          "\x30" + self.asn1encode(
            "\xa0" + self.asn1encode(
              "\x0a" + self.asn1encode(
                "\x00"
              )
            )
          )
        )
      return blob
    end

    # Return the correct ntlmflags upon the configuration
    def self.make_ntlm_flags(opt = {})

      signing 		= opt[:signing] 		!= nil ? opt[:signing] : false
      usentlm2_session 	= opt[:usentlm2_session]	!= nil ? opt[:usentlm2_session] : true
      use_ntlmv2 		= opt[:use_ntlmv2] 		!= nil ? opt[:use_ntlmv2] : false
      send_lm 		= opt[:send_lm] 		!= nil ? opt[:send_lm] : true
      send_ntlm 		= opt[:send_ntlm] 		!= nil ? opt[:send_ntlm] : true
      use_lanman_key 		= opt[:use_lanman_key] 		!= nil ? opt[:use_lanman_key] : false

      if signing
        ntlmssp_flags = 0xe2088215
      else

        ntlmssp_flags = 0xa2080205
      end

      if usentlm2_session
        if use_ntlmv2
          #set Negotiate Target Info
          ntlmssp_flags |= Rex::Proto::NTLM::Constants::NEGOTIATE_TARGET_INFO
        end

      else
        #remove the ntlm2_session flag
        ntlmssp_flags &= 0xfff7ffff
        #set lanmanflag only when lm and ntlm are sent
        if send_lm
          ntlmssp_flags |= Rex::Proto::NTLM::Constants::NEGOTIATE_LMKEY if use_lanman_key
        end
      end

      #we can also downgrade ntlm2_session when we send only lmv1
      ntlmssp_flags &= 0xfff7ffff if usentlm2_session && (not use_ntlmv2) && (not send_ntlm)

      return ntlmssp_flags
    end


    # Parse an ntlm type 2 challenge blob and return usefull data
    def self.parse_ntlm_type_2_blob(blob)
      data = {}
      # Extract the NTLM challenge key the lazy way
      cidx = blob.index("NTLMSSP\x00\x02\x00\x00\x00")

      if not cidx
        raise Rex::Proto::NTLM::Exceptions::NTLMMissingChallenge
      end

      data[:challenge_key] = blob[cidx + 24, 8]

      data[:server_ntlmssp_flags] = blob[cidx + 20, 4].unpack("V")[0]

      # Extract the address list from the blob
      alist_len,alist_mlen,alist_off = blob[cidx + 40, 8].unpack("vvV")
      alist_buf = blob[cidx + alist_off, alist_len]

      while(alist_buf.length > 0)
        atype, alen = alist_buf.slice!(0,4).unpack('vv')
        break if atype == 0x00
        addr = alist_buf.slice!(0, alen)
        case atype
        when 1
          #netbios name
          temp_name = addr
          temp_name.force_encoding("UTF-16LE")
          data[:default_name] =  temp_name.encode("UTF-8")
        when 2
          #netbios domain
          temp_domain = addr
          temp_domain.force_encoding("UTF-16LE")
          data[:default_domain] =  temp_domain.encode("UTF-8")
        when 3
          #dns name
          temp_dns = addr
          temp_dns.force_encoding("UTF-16LE")
          data[:dns_host_name] =  temp_dns.encode("UTF-8")
        when 4
          #dns domain
          temp_dns_domain = addr
          temp_dns_domain.force_encoding("UTF-16LE")
          data[:dns_domain_name] =  temp_dns_domain.encode("UTF-8")
        when 5
          #The FQDN of the forest.
        when 6
          #A 32-bit value indicating server or client configuration
        when 7
          #Client time
          data[:chall_MsvAvTimestamp] = addr
        when 8
          #A Restriction_Encoding structure
        when 9
          #The SPN of the target server.
        when 10
          #A channel bindings hash.
        end
      end
      return data
    end

    # This function return an ntlmv2 client challenge
    # This is a partial implementation, full description is in [MS-NLMP].pdf around 3.1.5.2.1 :-/
    def self.make_ntlmv2_clientchallenge(win_domain, win_name, dns_domain, dns_name,
              client_challenge = nil, chall_MsvAvTimestamp = nil, spnopt = {})

      client_challenge ||= Rex::Text.rand_text(8)
      # We have to set the timestamps here to the one in the challenge message from server if present
      # If we don't do that, recent server like Seven/2008 will send a STATUS_INVALID_PARAMETER error packet
      timestamp = chall_MsvAvTimestamp != '' ? chall_MsvAvTimestamp : self.time_unix_to_smb(Time.now.to_i).reverse.pack("VV")
      # Make those values unicode as requested
      win_domain = Rex::Text.to_unicode(win_domain)
      win_name = Rex::Text.to_unicode(win_name)
      dns_domain = Rex::Text.to_unicode(dns_domain)
      dns_name = Rex::Text.to_unicode(dns_name)
      # Make the AV_PAIRs
      addr_list  = ''
      addr_list  << [2, win_domain.length].pack('vv') + win_domain
      addr_list  << [1, win_name.length].pack('vv') + win_name
      addr_list  << [4, dns_domain.length].pack('vv') + dns_domain
      addr_list  << [3, dns_name.length].pack('vv') + dns_name
      addr_list  << [7, 8].pack('vv') + timestamp

      # Windows Seven / 2008r2 Request this type if in local security policies,
      # Microsoft network server : Server SPN target name validation level is set to <Required from client>
      # otherwise it send an STATUS_ACCESS_DENIED packet
      if spnopt[:use_spn]
        spn= Rex::Text.to_unicode("cifs/#{spnopt[:name] || 'unknown'}")
        addr_list  << [9, spn.length].pack('vv') + spn
      end

      # MAY BE USEFUL FOR FUTURE
      # Seven (client) add at least one more av that is of type MsAvRestrictions (8)
      # maybe this will be usefull with future windows OSs but has no use at all for the moment afaik
      # restriction_encoding = 	[48,0,0,0].pack("VVV") + # Size, Z4, IntegrityLevel, SubjectIntegrityLevel
      # 			Rex::Text.rand_text(32)	 # MachineId generated on startup on win7 and above
      # addr_list  << [8, restriction_encoding.length].pack('vv') + restriction_encoding

      # Seven (client) and maybe others versions also add an av of type MsvChannelBindings (10) but the hash is "\x00" * 16
      # addr_list  << [10, 16].pack('vv') + "\x00" * 16


      addr_list  << [0, 0].pack('vv')
      ntlm_clientchallenge = 	[1,1,0,0].pack("CCvV") + #RespType, HiRespType, Reserved1, Reserved2
            timestamp + #Timestamp
            client_challenge + 	#clientchallenge
            [0].pack("V")  +	#Reserved3
            addr_list + "\x00" * 4

    end

    # create lm/ntlm responses
    def self.create_lm_ntlm_responses(user, pass, challenge_key, domain = '', default_name = '', default_domain = '',
            dns_host_name = '', dns_domain_name = '', chall_MsvAvTimestamp = nil, spnopt = {}, opt = {} )

      usentlm2_session 	= opt[:usentlm2_session]	!= nil ? opt[:usentlm2_session] : true
      use_ntlmv2 		= opt[:use_ntlmv2] 		!= nil ? opt[:use_ntlmv2] : false
      send_lm 		= opt[:send_lm] 		!= nil ? opt[:send_lm] : true
      send_ntlm 		= opt[:send_ntlm] 		!= nil ? opt[:send_ntlm] : true

      #calculate the lm/ntlm response
      resp_lm = "\x00" * 24
      resp_ntlm = "\x00" * 24

      client_challenge = Rex::Text.rand_text(8)
      ntlm_cli_challenge = ''
      if send_ntlm  #should be default
        if usentlm2_session
          if use_ntlmv2
            ntlm_cli_challenge = self.make_ntlmv2_clientchallenge(
              default_domain, default_name, dns_domain_name,
              dns_host_name,client_challenge,
              chall_MsvAvTimestamp, spnopt)

            if self.is_pass_ntlm_hash?(pass)
              argntlm = {
                :ntlmv2_hash => Rex::Proto::NTLM::Crypt::ntlmv2_hash(
                          user,
                          [ pass.upcase()[33,65] ].pack('H32'),
                          domain,{:pass_is_hash => true}
                        ),
                :challenge   => challenge_key
              }
            else
              argntlm = {
                :ntlmv2_hash =>  Rex::Proto::NTLM::Crypt::ntlmv2_hash(user, pass, domain),
                :challenge   =>  challenge_key
              }
            end

            optntlm = { :nt_client_challenge => ntlm_cli_challenge}
            ntlmv2_response = Rex::Proto::NTLM::Crypt::ntlmv2_response(argntlm,optntlm)
            resp_ntlm = ntlmv2_response

            if send_lm
              if self.is_pass_ntlm_hash?(pass)
                arglm = {
                  :ntlmv2_hash =>  Rex::Proto::NTLM::Crypt::ntlmv2_hash(
                            user,
                            [ pass.upcase()[33,65] ].pack('H32'),
                            domain,{:pass_is_hash => true}
                          ),
                  :challenge   => challenge_key
                }
              else
                arglm = {
                  :ntlmv2_hash =>  Rex::Proto::NTLM::Crypt::ntlmv2_hash(user,pass, domain),
                  :challenge   => challenge_key
                }
              end

              optlm = { :client_challenge => client_challenge }
              resp_lm = Rex::Proto::NTLM::Crypt::lmv2_response(arglm, optlm)
            else
              resp_lm = "\x00" * 24
            end

          else # ntlm2_session
            if self.is_pass_ntlm_hash?(pass)
              argntlm = {
                :ntlm_hash =>  [ pass.upcase()[33,65] ].pack('H32'),
                :challenge => challenge_key
              }
            else
              argntlm = {
                :ntlm_hash =>  Rex::Proto::NTLM::Crypt::ntlm_hash(pass),
                :challenge => challenge_key
              }
            end

            optntlm = {	:client_challenge => client_challenge}
            resp_ntlm = Rex::Proto::NTLM::Crypt::ntlm2_session(argntlm,optntlm).join[24,24]

            # Generate the fake LANMAN hash
            resp_lm = client_challenge + ("\x00" * 16)
          end

        else # we use lmv1/ntlmv1
          if self.is_pass_ntlm_hash?(pass)
            argntlm = {
              :ntlm_hash =>  [ pass.upcase()[33,65] ].pack('H32'),
              :challenge =>  challenge_key
            }
          else
            argntlm = {
              :ntlm_hash =>  Rex::Proto::NTLM::Crypt::ntlm_hash(pass),
              :challenge =>  challenge_key
            }
          end

          resp_ntlm = Rex::Proto::NTLM::Crypt::ntlm_response(argntlm)
          if send_lm
            if self.is_pass_ntlm_hash?(pass)
              arglm = {
                :lm_hash => [ pass.upcase()[0,32] ].pack('H32'),
                :challenge =>  challenge_key
              }
            else
              arglm = {
                :lm_hash => Rex::Proto::NTLM::Crypt::lm_hash(pass),
                :challenge =>  challenge_key
              }
            end
            resp_lm = Rex::Proto::NTLM::Crypt::lm_response(arglm)
          else
            #when windows does not send lm in ntlmv1 type response,
            # it gives lm response the same value as ntlm response
            resp_lm  = resp_ntlm
          end
        end
      else #send_ntlm = false
        #lmv2
        if usentlm2_session && use_ntlmv2
          if self.is_pass_ntlm_hash?(pass)
            arglm = {
              :ntlmv2_hash =>  Rex::Proto::NTLM::Crypt::ntlmv2_hash(
                        user,
                        [ pass.upcase()[33,65] ].pack('H32'),
                        domain,{:pass_is_hash => true}
                      ),
              :challenge => challenge_key
            }
          else
            arglm = {
              :ntlmv2_hash =>  Rex::Proto::NTLM::Crypt::ntlmv2_hash(user,pass, domain),
              :challenge => challenge_key
            }
          end
          optlm = { :client_challenge => client_challenge }
          resp_lm = Rex::Proto::NTLM::Crypt::lmv2_response(arglm, optlm)
        else
          if self.is_pass_ntlm_hash?(pass)
            arglm = {
              :lm_hash => [ pass.upcase()[0,32] ].pack('H32'),
              :challenge =>  challenge_key
            }
          else
            arglm = {
              :lm_hash => Rex::Proto::NTLM::Crypt::lm_hash(pass),
              :challenge =>  challenge_key
            }
          end
          resp_lm = Rex::Proto::NTLM::Crypt::lm_response(arglm)
        end
        resp_ntlm = ""
      end
      return resp_lm, resp_ntlm, client_challenge, ntlm_cli_challenge
    end

    # create the session key
    def self.create_session_key(ntlmssp_flags, server_ntlmssp_flags, user, pass, domain, challenge_key,
            client_challenge = '', ntlm_cli_challenge = '' , opt = {} )

      usentlm2_session 	= opt[:usentlm2_session]	!= nil ? opt[:usentlm2_session] : true
      use_ntlmv2 		= opt[:use_ntlmv2] 		!= nil ? opt[:use_ntlmv2] : false
      send_lm 		= opt[:send_lm] 		!= nil ? opt[:send_lm] : true
      send_ntlm 		= opt[:send_ntlm] 		!= nil ? opt[:send_ntlm] : true
      use_lanman_key 		= opt[:use_lanman_key] 		!= nil ? opt[:use_lanman_key] : false

      # Create the sessionkey (aka signing key, aka mackey) and encrypted session key
      # Server will decide for key_size and key_exchange
      enc_session_key = ''
      signing_key = ''

      # Set default key size and key exchange values
      key_size = 40
      key_exchange = false
      # Remove ntlmssp.negotiate56
      ntlmssp_flags &= 0x7fffffff
      # Remove ntlmssp.negotiatekeyexch
      ntlmssp_flags &= 0xbfffffff
      # Remove ntlmssp.negotiate128
      ntlmssp_flags &= 0xdfffffff
      # Check the keyexchange
      if server_ntlmssp_flags & Rex::Proto::NTLM::Constants::NEGOTIATE_KEY_EXCH != 0 then
        key_exchange = true
        ntlmssp_flags |= Rex::Proto::NTLM::Constants::NEGOTIATE_KEY_EXCH
      end
      # Check 128bits
      if server_ntlmssp_flags & Rex::Proto::NTLM::Constants::NEGOTIATE_128 != 0 then
        key_size = 128
        ntlmssp_flags |= Rex::Proto::NTLM::Constants::NEGOTIATE_128
        ntlmssp_flags |= Rex::Proto::NTLM::Constants::NEGOTIATE_56
      # Check 56bits
      else
        if server_ntlmssp_flags & Rex::Proto::NTLM::Constants::NEGOTIATE_56 != 0 then
          key_size = 56
          ntlmssp_flags |= Rex::Proto::NTLM::Constants::NEGOTIATE_56
        end
      end
      # Generate the user session key
      lanman_weak = false
      if send_ntlm  # Should be default
        if usentlm2_session
          if use_ntlmv2
            if self.is_pass_ntlm_hash?(pass)
              user_session_key = Rex::Proto::NTLM::Crypt::ntlmv2_user_session_key(user,
                          [ pass.upcase()[33,65] ].pack('H32'),
                          domain,
                          challenge_key, ntlm_cli_challenge,
                          {:pass_is_hash => true})
            else
              user_session_key = Rex::Proto::NTLM::Crypt::ntlmv2_user_session_key(user, pass, domain,
                        challenge_key, ntlm_cli_challenge)
            end
          else
            if self.is_pass_ntlm_hash?(pass)
              user_session_key = Rex::Proto::NTLM::Crypt::ntlm2_session_user_session_key([ pass.upcase()[33,65] ].pack('H32'),
                              challenge_key,
                              client_challenge,
                              {:pass_is_hash => true})
            else
              user_session_key = Rex::Proto::NTLM::Crypt::ntlm2_session_user_session_key(pass, challenge_key,
                              client_challenge)
            end
          end
        else # lmv1/ntlmv1
          # lanman_key may also be used without ntlm response but it is not so much used
          # so we don't care about this feature
          if send_lm && use_lanman_key
            if self.is_pass_ntlm_hash?(pass)
              user_session_key = Rex::Proto::NTLM::Crypt::lanman_session_key([ pass.upcase()[0,32] ].pack('H32'),
                          challenge_key,
                          {:pass_is_hash => true})
            else
              user_session_key = Rex::Proto::NTLM::Crypt::lanman_session_key(pass, challenge_key)
            end
            lanman_weak = true


          else
            if self.is_pass_ntlm_hash?(pass)
              user_session_key = Rex::Proto::NTLM::Crypt::ntlmv1_user_session_key([ pass.upcase()[33,65] ].pack('H32'),
                            {:pass_is_hash => true})
            else
              user_session_key = Rex::Proto::NTLM::Crypt::ntlmv1_user_session_key(pass)
            end
          end
        end
      else
          if usentlm2_session && use_ntlmv2
            if self.is_pass_ntlm_hash?(pass)
              user_session_key = Rex::Proto::NTLM::Crypt::lmv2_user_session_key(user, [ pass.upcase()[33,65] ].pack('H32'),
                          domain,
                          challenge_key, client_challenge,
                          {:pass_is_hash => true})
            else
              user_session_key = Rex::Proto::NTLM::Crypt::lmv2_user_session_key(user, pass, domain,
                          challenge_key, client_challenge)
            end
          else
            if self.is_pass_ntlm_hash?(pass)
              user_session_key = Rex::Proto::NTLM::Crypt::lmv1_user_session_key([ pass.upcase()[0,32] ].pack('H32'),
                            {:pass_is_hash => true})
            else
              user_session_key = Rex::Proto::NTLM::Crypt::lmv1_user_session_key(pass)
            end
          end
      end

      user_session_key = Rex::Proto::NTLM::Crypt::make_weak_sessionkey(user_session_key,key_size, lanman_weak)

      # Sessionkey and encrypted session key
      if key_exchange
        signing_key = Rex::Text.rand_text(16)
        enc_session_key = Rex::Proto::NTLM::Crypt::encrypt_sessionkey(signing_key, user_session_key)
      else
        signing_key = user_session_key
      end

      return signing_key, enc_session_key, ntlmssp_flags
    end
  end
end
