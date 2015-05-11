##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex'

class Metasploit3 < Msf::Post

  include Msf::Post::File

  def initialize(info={})
    super( update_info( info,
      'Name'          => 'FileDropper code test case',
      'Description'   => %q{ Test case for issue #4667 },
      'License'       => MSF_LICENSE,
      'Author'        => [ 'juan vazquez' ],
      'Platform'      => %w{ linux osx unix win java php python },
      'SessionTypes'  => [ 'shell', 'meterpreter' ]
    ))
  end

  def check_file(file, win_file)
    if session.platform =~ /win/
      res = file_exist?(win_file)
    else
      res = file_exist?(file)
    end

    res
  end

  def file_deleted?(file, win_file, exists_before)
    if exists_before
      if check_file(file, win_file)
        print_error("Unable to delete #{file}")
        false
      else
        print_good("Deleted #{file}")
        true
      end
    else
      print_warning("Tried to delete #{file}, unknown result")
      true
    end
  end

  def run
    @dropped_files = [
      '/tmp/test1.txt',
      '/tmp/test2.txt',
      '/tmp/test3.txt'
    ]

    @dropped_files.delete_if do |file|
      print_status("Trying to delete #{file}... ")
      win_file = file.gsub("/", "\\\\")
      exists_before = check_file(file, win_file)

      if session.type == "meterpreter"
        begin
          # Meterpreter should do this automatically as part of
          # fs.file.rm().  Until that has been implemented, remove the
          # read-only flag with a command.
          if session.platform =~ /win/
            session.shell_command_token(%Q|attrib.exe -r #{win_file}|)
          end
          session.fs.file.rm(file)
        rescue ::Rex::Post::Meterpreter::RequestError
          return false
        end
        file_deleted?(file, win_file, exists_before)
      else
        win_cmds = [
          %Q|attrib.exe -r "#{win_file}"|,
          %Q|del.exe /f /q "#{win_file}"|
        ]
        # We need to be platform-independent here. Since we can't be
        # certain that {#target} is accurate because exploits with
        # automatic targets frequently change it, we just go ahead and
        # run both a windows and a unix command in the same line. One
        # of them will definitely fail and the other will probably
        # succeed. Doing it this way saves us an extra round-trip.
        # Trick shared by @mihi42
        session.shell_command_token("rm -f \"#{file}\" >/dev/null ; echo ' & #{win_cmds.join(" & ")} & echo \" ' >/dev/null")
        file_deleted?(file, win_file, exists_before)
      end
    end
  end

end
