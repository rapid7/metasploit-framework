##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::Android::Priv

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Multiplatform Installed Software Version Enumerator',
        'Description' => %q{
          This module, when run against a compromised machine, will gather details on all installed software,
          including their versions and if available, when they were installed, and will save it into a loot file for later use.
          Users can then use this loot file to determine what additional vulnerabilites may affect the target machine.

          Note that for Linux systems, software enumeration is done via package managers. As a result the results may
          not reflect all of the available software on the system simply because users may have installed additional
          software from alternative sources such as source code that these package managers are not aware of.
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

  def enumerate_android_packages
    if command_exists?('pm') == false
      print_error("The command 'pm' does not exist on the host")
      return nil
    end
    listing = cmd_exec('pm list packages -f').to_s
    if listing.empty?
      print_error('No results were returned when trying to get software installed on the Linux host. An error likely occured.')
      return nil
    end
    listing
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
      # and further verified against VMs that were set up in testing labs.
      if command_exists?('apt') # Debian, Ubuntu, and Debian derived distros.
        cmd = %w[apt list --installed]
      elsif command_exists?('dpkg') # Alternative for Debian based systems
        cmd = %w[dpkg -l]
      elsif command_exists?('pacman') # Arch and Manjaro are two popular examples
        cmd = %w[pacman -Q]
      elsif command_exists?('zypper') # OpenSUSE is a popular example
        cmd = %w[zypper search -is]
      elsif command_exists?('rpm') # Fedora, Centos, RHEL
        cmd = %w[rpm -qa]
      elsif command_exists?('apk') # Apline
        cmd = %w[apk info -v]
      elsif command_exists?('qlist') # Gentoo
        cmd = %w[qlist -Iv]
      elsif command_exists?('pkg') # FreeBSD
        cmd = %w[pkg info]
      elsif command_exists?('equo') # Sabayon
        cmd = %w[equo q list installed -v]
      elsif command_exists?('nix-env')
        cmd = %w[nix-env -q]
      else
        print_error("The target system either doesn't have a package manager system, or does not use a known package manager system!")
        print_error('Unable to enumerate the software on the target system. Exiting...')
        return nil
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
      listing = ''
      if command_exists?('system_profiler') == false
        print_error("The command 'system_profiler' does not exist on the host! Something is seriously wrong!")
        return
      end
      command_result = cmd_exec('system_profiler SPApplicationsDataType').to_s
      if command_result.empty?
        print_error('No results were returned when trying to get software installed on the OSX host via system_profiler!')
        return
      end
      listing += command_result

      # Start enumerating other potential MacOS package managers now that
      # the main system app manager has been enumerated.
      if command_exists?('brew') # HomeBrew
        listing += "\n\n----------------Brew Packages----------------\n"
        listing += cmd_exec('brew list --versions')
      end

      if command_exists?('port') # MacPorts
        listing += "\n\n----------------MacPorts Packages----------------\n"
        listing += cmd_exec('port installed')
      end

      file = store_loot('host.osx.software.versions', 'text/plain', session, listing, 'installed_software.txt', 'Installed Software and Versions')
      print_good("Stored information about the installed products to the loot file at #{file}")
    when 'android'
      if is_root?
        if command_exists?('dumpsys') == false
          print_error("Something is odd with this Android device. You are root but the dumpsys command doesn't exist. Perhaps the device is too old?")
          return
        end
        listing = cmd_exec('dumpsys package packages').to_s
        if listing.empty?
          print_error('Something went wrong with the command and no output was returned!')
          return
        elsif listing =~ /android.permission.DUMP/
          print_warning('You do not have the permissions needed to dump the versions of software installed. Reverting to just enumerating what software is installed.')
          listing = enumerate_android_packages
          return if listing.nil?
        end
      else
        print_warning('You do not have the permissions needed to dump the versions of software installed. Reverting to just enumerating what software is installed.')
        listing = enumerate_android_packages
        return if listing.nil?
      end
      file = store_loot('host.android.software.versions', 'text/plain', session, listing, 'installed_software.txt', 'Installed Software and Versions')
      print_good("Stored information about the installed products to the loot file at #{file}")
    end
  end
end
