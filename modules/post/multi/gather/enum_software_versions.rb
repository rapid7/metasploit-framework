##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Multiplatform Installed Software Version Enumerator',
        'Description' => %q{
          This module, when run against a compromised machine, will gather details on all installed software,
          including their versions and if available, when they were installed, and will save it into a loot file for later use.
          Users can then use this loot file to determine what additional vulnerabilites may affect the target machine.
        },
        'License' => MSF_LICENSE,
        'Author' => [ 'gwillcox-r7' ],
        'Platform' => %w[win linux osx bsd solaris android],
        'SessionTypes' => [ 'meterpreter', 'shell' ]
      )
    )
  end

  def store_linux_loot(listing)
    file = store_loot('host.linux.software.versions', 'text/plain', session, listing, 'installed_software.txt', 'Installed Software and Versions')
    print_good("Stored information about the installed products to the loot file at #{file}")
  end

  # Run Method for when run command is issued
  def run
    case session.platform
    when 'windows'
      if command_exists?('wmic') == false
        print_error("The 'wmic' command doesn't exist on this host!") # wmic is technically marked as depreciated so this command could very well be removed in future releases.
        return
      end
      listing = cmd_exec('wmic product get Name, Description, Version, InstallDate', nil, 6000).to_s
      unless listing.include?('Description')
        print_error('Was unable to get a listing of installed products...')
        return
      end
      file = store_loot('host.windows.software.versions', 'text/plain', session, listing, 'installed_software.txt', 'Installed Software and Versions')
      print_good("Stored information about the installed products to the loot file at #{file}")
    when 'linux'
      # All of the following options were taken from https://distrowatch.com/dwres.php?resource=package-management
      cmd = %w[hostnamectl]
      if command_exists?('hostnamectl') == false
        print_error("The 'hostnamectl' command doesn't exist on the host, so we can't enumerate what OS this Linux host is running!")
        return
      end
      operating_system = cmd_exec(cmd[0]).to_s
      if operating_system.empty?
        print_error('No results were returned when trying to determine the OS. An error likely occured.')
        return
      end
      case operating_system
      when /(?:[uU]buntu|[dD]ebian|[eE]lementary|[mM]int|MX|[zZ]orin|[kK]ali)/
        cmd = %w[apt list --installed]
      when /(?: [aA]rch |[mM]anjaro)/
        cmd = %w[pacman -Q]
      when /opensuse/i
        cmd = %w[zypper search -is]
      when /(?:fedora|centos|red hat enterprise linux)/i
        cmd = %w[rpm -qa]
      when /alpine/i
        cmd = %w[apk info]
      when /gentoo/i
        cmd = %w[qlist -i]
      when /freebsd/i
        cmd = %w[pkg info]
      end

      if command_exists?((cmd[0]).to_s) == false
        print_error("The command #{cmd[0]} was not found on the target.")
        return
      else
        listing = cmd_exec(cmd.join(' ')).to_s
        if listing.empty?
          print_error('No results were returned when trying to get software installed on the Linux host. An error likely occured.')
          return
        end
        store_linux_loot(listing)
      end
    when 'bsd', 'solaris'
      if command_exists?('pkg') == false
        print_error("The command 'pkg' does not exist on the host")
        return
      end
      listing = cmd_exec('pkg info').to_s
      if listing.empty?
        print_error('No results were returned when trying to get software installed on the BSD/Solaris host. An error likely occured.')
        return
      end
      file = store_loot('host.bsd.solaris.software.versions', 'text/plain', session, listing, 'installed_software.txt', 'Installed Software and Versions')
      print_good("Stored information about the installed products to the loot file at #{file}")
    when 'osx'
      if command_exists?('system_profiler') == false
        print_error("The command 'system_profiler' does not exist on the host")
        return
      end
      listing = cmd_exec('system_profiler SPApplicationsDataType').to_s
      if listing.empty?
        print_error('No results were returned when trying to get software installed on the OSX host. An error likely occured.')
        return
      end
      file = store_loot('host.osx.software.versions', 'text/plain', session, listing, 'installed_software.txt', 'Installed Software and Versions')
      print_good("Stored information about the installed products to the loot file at #{file}")
    when 'android'
      if command_exists?('pm') == false
        print_error("The command 'pm' does not exist on the host")
        return
      end
      listing = cmd_exec('pm list packages -f').to_s
      if listing.empty?
        print_error('No results were returned when trying to get software installed on the Linux host. An error likely occured.')
        return
      end
      file = store_loot('host.android.software.versions', 'text/plain', session, listing, 'installed_software.txt', 'Installed Software and Versions')
      print_good("Stored information about the installed products to the loot file at #{file}")
    end
  end
end
