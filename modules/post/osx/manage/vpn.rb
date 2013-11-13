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
      connected_names = parse_vpn_connection_names(data, :connected)
      disconnected_names = parse_vpn_connection_names(data, :disconnected)
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
      vpn_change_state(datastore['VPN_CONNECTION'], :up)
    elsif action.name == 'DISCONNECT'
      vpn_change_state(datastore['VPN_CONNECTION'], :down)
    end
  end

  def get_vpn_list()
    vprint_status(datastore['SCUTIL_PATH'].shellescape + " --nc list")
    data = cmd_exec(datastore['SCUTIL_PATH'].shellescape + " --nc list")
    return data
  end

  def parse_vpn_connection_names(data, type= :connected)
    lines = data.lines
    connection_names = []
    comp_str = type == :connected ? STR_CONNECTED : STR_DISCONNECTED

    lines.each do |line|
      line.strip!
      parts = line.split('"')
      connection_names << parts[1] if line.start_with?(comp_str) && parts.length > 1
    end
    return connection_names
  end

  def vpn_change_state(vpn_name, state)
    case state
    when :up
      header = "Connecting to VPN: #{vpn_name}"
      connection_state = STR_CONNECTED
      connection_unnecessary = "#{vpn_name} already connected"
    when :down
      header = "Disconnecting from VPN: #{vpn_name}"
      connection_state = STR_DISCONNECTED
      connection_unnecessary = "#{vpn_name} already disconnected"
    else
      raise ArgumentError.new("VPN state argument must be :up or :down")
    end

    print_status(header)
    identifier = nil
    data = get_vpn_list()
    lines = data.lines
    lines.each do |line|
      line.strip!
      next if line.empty?
      parts = line.split('"')
      if (parts.length >= 2 && parts[1] == vpn_name)
        if line.start_with?(connection_state)
          print_status(connection_unnecessary)
          return true
        end
        potential_ids = line.split(' ')
        if potential_ids.length >= 3
          identifier = potential_ids[2]
          break
        end
      end
    end

    if identifier.nil?
      print_error("#{vpn_name} not found")
      return false
    end

    case state
    when :up
      cmd = datastore['NETWORKSETUP_PATH'].shellescape + " -connectpppoeservice '#{vpn_name}'"
    when :down
      cmd = datastore['SCUTIL_PATH'].shellescape + " --nc stop #{identifier}"
    else
      raise ArgumentError.new("VPN state argument must be :up or :down")
    end
    vprint_status(cmd)
    cmd_exec(cmd)
  end
end
