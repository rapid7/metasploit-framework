##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'Belkin Wemo-Enabled Crock-Pot Remote Control',
      'Description'   => %q{
        This module acts as a simple remote control for Belkin Wemo-enabled
        Crock-Pots by implementing a subset of the functionality provided by the
        Wemo App.

        No vulnerabilities are exploited by this Metasploit module in any way.
      },
      'Author'        => 'wvu',
      'References'    => [
        ['URL', 'https://www.crock-pot.com/wemo-landing-page.html'],
        ['URL', 'https://www.belkin.com/us/support-article?articleNum=101177'],
        ['URL', 'http://www.wemo.com/']
      ],
      'License'       => MSF_LICENSE,
      'Actions'       => [
        ['Cook', 'Description' => 'Cook stuff'],
        ['Stop', 'Description' => 'Stop cooking']
      ],
      'DefaultAction' => 'Cook',
      'Notes'         => {
        'Stability'   => [CRASH_SAFE],
        'SideEffects' => [PHYSICAL_EFFECTS]
      }
    ))

    register_options([
      Opt::RPORT(49152),
      OptEnum.new('TEMP', [true, 'Temperature', 'Off', modes.keys]),
      OptInt.new('TIME',  [true, 'Cook time in minutes', 0])
    ])

    register_advanced_options([
      OptBool.new('DefangedMode', [true, 'Run in defanged mode', true]),
      OptBool.new('ForceExploit', [true, 'Override check result', false])
    ])
  end

  def check
    res = send_request_cgi(
      'method' => 'GET',
      'uri'    => '/setup.xml'
    )

    if res && res.code == 200 && res.body.include?('urn:Belkin:device:')
      if res.body.include?('urn:Belkin:device:crockpot:1')
        vprint_good('Wemo-enabled Crock-Pot detected')
        return Exploit::CheckCode::Appears
      end

      vprint_status('Wemo device detected, but it is not a Crock-Pot')
      return Exploit::CheckCode::Detected
    end

    Exploit::CheckCode::Safe
  end

  def run
    if datastore['DefangedMode']
      print_error('Running in defanged mode')
      return
    end

    checkcode = check

    unless checkcode == Exploit::CheckCode::Appears || datastore['ForceExploit']
      print_error("#{checkcode[1]}. Set ForceExploit to override.")
      return
    end

    case action.name
    when 'Cook'
      print_status("Cooking on #{datastore['TEMP']} for #{datastore['TIME']}m")
      res = send_request_cook(datastore['TEMP'], datastore['TIME'])
    when 'Stop'
      print_status('Setting temperature to Off and cook time to 0m')
      res = send_request_cook('Off', 0)
    end

    unless res && res.code == 200 && (time = res.get_xml_document.at('//time'))
      print_error("Failed to #{action.name.downcase}, aborting!")
      return
    end

    print_good("Cook time set to #{time.text}m")
  end

  def send_request_cook(temp, time)
    send_request_cgi(
      'method'       => 'POST',
      'uri'          => '/upnp/control/basicevent1',
      'ctype'        => 'text/xml',
      'headers'      => {
        'SOAPACTION' => '"urn:Belkin:service:basicevent:1#SetCrockpotState"'
      },
      'data'         => generate_soap_xml(temp, time)
    )
  end

  def generate_soap_xml(temp, time)
    <<~EOF
      <?xml version="1.0" encoding="utf-8"?>
      <s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
        <s:Body>
          <u:SetCrockpotState xmlns:u="urn:Belkin:service:basicevent:1">
            <mode>#{modes[temp]}</mode>
            <time>#{time}</time>
          </u:SetCrockpotState>
        </s:Body>
      </s:Envelope>
    EOF
  end

  def modes
    {
      'Off'  => 0,
      'Warm' => 50,
      'Low'  => 51,
      'High' => 52
    }
  end

end
