##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post

  def initialize(info={})
    super( update_info( info,
        'Name'          => 'Multiplatform Installed Software Version',
        'Description'   => %q{ This module, when run against a compromised machine, will gather details on all installed software, 
        including their versions and if available, when they were installed, and will save it into a loot file for later use. 
        Users can then use this loot file to determine what additional vulnerabilites may affect the target machine. },
        'License'       => MSF_LICENSE,
        'Author'        => [ 'gwillcox-r7' ],
        'Platform'      => %w{ win linux osx bsd solaris android },
        #'Platform'      => %w{ android osx win linux bsd solaris },
        'SessionTypes'  => [ 'meterpreter', 'shell' ],
      ))
  end

  def store_linux_loot(listing)
    file = store_loot("host.linux.software.versions", "text/plain", session, listing, "installed_software.txt", "Installed Software and Versions")
    print_good("Stored information about the installed products to the loot file at #{file}")
  end

  # Run Method for when run command is issued
  def run
    case session.platform
    when 'windows'
        listing = cmd_exec('wmic product get Name, Description, Version, InstallDate', nil, 6000)
        unless listing =~ /Description/
            print_error("Was unable to get a listing of installed products...")
            return nil
        end
        file = store_loot("host.windows.software.versions", "text/plain", session, listing, "installed_software.txt", "Installed Software and Versions")
        print_good("Stored information about the installed products to the loot file at #{file}")
    when 'linux'
        # All of the following options were taken from https://distrowatch.com/dwres.php?resource=package-management
        operating_system = cmd_exec('hostnamectl')
        if operating_system =~ /not found/
            print_error("Can't determine the host's OS, as the 'hostnamectl' command was not found")
            return nil
        elsif operating_system =~ /ubuntu/i || operating_system =~ /debian/i || operating_system =~ /elementary/i || operating_system =~ /mint/i || operating_system =~ /MX/ || operating_system =~ /zorin/i || operating_system =~ /kali/i
            listing = cmd_exec('apt list --installed')
            if listing =~ /not found/
                print_error("The command 'apt' does not exist on the host")
                return nil
            end
            unless listing =~ /listing\.\./i
                print_error("Was unable to dump the versions of software installed!")
                return nil
            end
            store_linux_loot(listing)
        elsif operating_system =~ / [aA]rch / || operating_system =~ /manjaro/i
            listing = cmd_exec('pacman -Q')
            if listing =~ /not found/
                print_error("The command 'pacman' does not exist on the host")
                return nil
            end
            store_linux_loot(listing)
        elsif operating_system =~ /opensuse/i
            listing = cmd_exec('zypper search -is')
            if listing =~ /not found/
                print_error("The command 'zypper' does not exist on the host")
                return nil
            end
            store_linux_loot(listing)
        elsif operating_system =~ /fedora/i || operating_system =~ /centos/i
            listing = cmd_exec('rpm -qa')
            if listing =~ /not found/
                print_error("The command 'rpm' does not exist on the host")
                return nil
            end
            store_linux_loot(listing)
        elsif operating_system =~ /alpine/i
            listing = cmd_exec('apk info')
            if listing =~ /not found/
                print_error("The command 'apk' does not exist on the host")
                return nil
            end
            store_linux_loot(listing)
        elsif operating_system =~ /gentoo/i
            listing = cmd_exec('qlist -i')
            if listing =~ /not found/
                print_error("The command 'qlist' does not exist on the host")
                return nil
            end
            store_linux_loot(listing)
        elsif operating_system =~ /freebsd/i
            listing = cmd_exec('pkg info')
            if listing =~ /not found/
                print_error("The command 'pkg' does not exist on the host")
                return nil
            end
            store_linux_loot(listing)
        else
            print_error("The target's operating system is not supported at this time.")
            return nil
        end
    when 'bsd'
        listing = cmd_exec('pkg info')
        if listing =~ /not found/
            print_error("The command 'pkg' does not exist on the host")
            return nil
        end
        store_linux_loot(listing)
    when 'osx'
        listing = cmd_exec('system_profiler SPApplicationsDataType')
        if listing =~ /not found/
            print_error("The command 'system_profiler' does not exist on the host")
            return nil
        end
        file = store_loot("host.osx.software.versions", "text/plain", session, listing, "installed_software.txt", "Installed Software and Versions")
        print_good("Stored information about the installed products to the loot file at #{file}")
    when 'solaris'
        listing = cmd_exec('pkg info')
        if listing =~ /not found/
            print_error("The command 'pkg' does not exist on the host")
            return nil
        end
        file = store_loot("host.solaris.software.versions", "text/plain", session, listing, "installed_software.txt", "Installed Software and Versions")
        print_good("Stored information about the installed products to the loot file at #{file}")
    when 'android'
        listing = cmd_exec('pm list packages -f')
    end

  rescue Rex::TimeoutError, Rex::Post::Meterpreter::RequestError
  rescue ::Exception => e
    print_status("The following error was encountered: #{e.class} #{e}")
  end
end
