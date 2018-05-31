##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Linux::Vulnerateca

  def initialize
    super(
      'Name'         => 'Vulnerateca Fingerprinting Module',
      'Description'  => %q{
        This module will be applied on a session connected to a shell. It will
        extract different information from target system.
      },
      'Author'       => 'Alberto Rafael Rodriguez Iglesias <security[at]vulnerateca.com> <albertocysec[at]gmail.com>',
      'License'      => MSF_LICENSE,
      'Platform'     => ['linux'],
      'SessionTypes' => ['shell']
    )
  end

  def run
    print_status(" -- Session Information --")
    print "Current Shell: " + vulnerateca_shell()[0]
    current_user = vulnerateca_whoami()[0]
    print "\nCurrent User: " + current_user
    print "\nIs Current User root?: " + vulnerateca_isroot?(current_user)[0]
    print "\nCurrent Shell PID: " + vulnerateca_shell_pid().to_s
    print "\n"
    print "\n"

    print_status(" -- System Information --")
    print "Current PATH env ($PATH): " + vulnerateca_path()[0]
    print "\n"
    print "\n"    

    print_status(" -- Network Information --")
    print "\n"
    print_good("List of local IPs:")
    ips = vulnerateca_ips()
    ips.each do |ip|
	print "\n" + ip
    end

    print "\n"
    print "\n"
    print_good("List of local network interfaces:")
    ifaces = vulnerateca_interfaces()
    ifaces.each do |iface|
        print "\n" + iface
    end

    print "\n"
    print "\n"
    print_good("List of local MAC addresses:")
    macs = vulnerateca_macs()
    macs.each do |mac|
        print "\n" +mac
    end

    print "\n"
    print "\n"
    print_good("List of listening TCP ports:")
    tcp_ports = vulnerateca_listen_tcp_ports()
    tcp_ports.each do |tcp_port|
        print "\n" + tcp_port.to_s
    end

    print "\n"
    print "\n"
    print_good("List of listening UDP ports:")
    udp_ports = vulnerateca_listen_udp_ports()
    udp_ports.each do |udp_port|
        print udp_port.to_s + "\n"
    end
    print "\n"
  end
end
