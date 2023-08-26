##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Module::Deprecated

  moved_from 'auxiliary/scanner/elasticsearch/indices_enum'

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Elasticsearch Enumeration Utility',
        'Description' => %q{
          This module enumerates Elasticsearch instances. It uses the REST API
          in order to gather information about the server, the cluster, nodes,
          in the cluster, indicies, and pull data from those indicies.
        },
        'Author' => [
          'Silas Cutler <Silas.Cutler[at]BlackListThisDomain.com>', # original indicies enum module
          'h00die' # generic enum module
        ],
        'References' => [
          ['URL', 'https://www.elastic.co/guide/en/elasticsearch/reference/current/rest-apis.html']
        ],
        'License' => MSF_LICENSE,
        'DefaultOptions' => {
          'SSL' => true
        },
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => [IOC_IN_LOGS]
        }
      )
    )

    register_options(
      [
        Opt::RPORT(9200),
        OptString.new('USERNAME', [false, 'A specific username to authenticate as', '']),
        OptString.new('PASSWORD', [false, 'A specific password to authenticate as', '']),
        OptInt.new('DOWNLOADROWS', [true, 'Number of beginning and ending rows to download per index', 5])
      ]
    )
  end

  def get_results(index)
    vprint_status("Downloading #{datastore['DOWNLOADROWS']} rows from index #{index}")
    body = { 'query' => { 'query_string' => { 'query' => '*' } }, 'size' => datastore['DOWNLOADROWS'], 'from' => 0, 'sort' => [] }
    request = {
      'uri' => normalize_uri(target_uri.path, index, '_search/'),
      'method' => 'POST',
      'headers' => {
        'Accept' => 'application/json'
      },
      'ctype' => 'application/json',
      'data' => body.to_json
    }
    request['authorization'] = basic_auth(datastore['USERNAME'], datastore['PASSWORD']) if datastore['USERNAME'] || datastore['PASSWORD']

    res = send_request_cgi(request)
    vprint_error('Unable to establish connection') if res.nil?

    if res && res.code == 200 && !res.body.empty?
      json_body = res.get_json_document
      if json_body.empty?
        vprint_error('Unable to parse JSON')
        return
      end
    else
      vprint_error('Timeout or unexpected response...')
      return
    end

    columns = json_body.dig('hits', 'hits')[0]['_source'].keys
    elastic_table = Rex::Text::Table.new(
      'Header' => "#{index} Data",
      'Indent' => 2,
      # we know at least 1 row since we wouldn't query an index w/o a row
      'Columns' => columns
    )
    json_body.dig('hits', 'hits').each do |hash|
      elastic_table << columns.map { |column| hash['_source'][column] }
    end

    l = store_loot('elasticserch.index.data', 'application/csv', rhost, elastic_table.to_csv, "#{index}_data.csv", nil, @service)
    print_good("#{index} data stored to #{l}")
  end

  def get_indices
    vprint_status('Querying indices...')
    request = {
      'uri' => normalize_uri(target_uri.path, '_cat', 'indices/'),
      'method' => 'GET',
      'headers' => {
        'Accept' => 'application/json'
      },
      'vars_get' => {
        # this is the query https://github.com/cars10/elasticvue uses for the chrome browser extension
        'h' => 'index,health,status,uuid,docs.count,store.size',
        'bytes' => 'mb'
      }
    }
    request['authorization'] = basic_auth(datastore['USERNAME'], datastore['PASSWORD']) if datastore['USERNAME'] || datastore['PASSWORD']

    res = send_request_cgi(request)
    vprint_error('Unable to establish connection') if res.nil?

    if res && res.code == 200 && !res.body.empty?
      json_body = res.get_json_document
      if json_body.empty?
        vprint_error('Unable to parse JSON')
        return
      end
    else
      vprint_error('Timeout or unexpected response...')
      return
    end

    elastic_table = Rex::Text::Table.new(
      'Header' => 'Indicies Information',
      'Indent' => 2,
      'Columns' =>
      [
        'Name',
        'Health',
        'Status',
        'UUID',
        'Documents',
        'Storage Usage (MB)'
      ]
    )

    indicies = []

    json_body.each do |index|
      next if datastore['VERBOSE'] == false && index['index'].starts_with?('.fleet')

      indicies << index['index'] if index['docs.count'].to_i > 0 # avoid querying something with no data
      elastic_table << [
        index['index'],
        index['health'],
        index['status'],
        index['uuid'],
        index['docs.count'],
        "#{index['store.size']}MB"
      ]
      report_note(
        host: rhost,
        port: rport,
        proto: 'tcp',
        type: 'elasticsearch.index',
        data: index[0],
        update: :unique_data
      )
    end

    print_good(elastic_table.to_s)
    indicies.each do |index|
      get_results(index)
    end
  end

  def get_cluster_info
    vprint_status('Querying cluster information...')
    request = {
      'uri' => normalize_uri(target_uri.path, '_cluster', 'health'),
      'method' => 'GET'
    }
    request['authorization'] = basic_auth(datastore['USERNAME'], datastore['PASSWORD']) if datastore['USERNAME'] || datastore['PASSWORD']

    res = send_request_cgi(request)

    fail_with(Failure::Unreachable, "#{peer} - Could not connect to web service - no response") if res.nil?
    fail_with(Failure::NoAccess, 'Credentials required, or incorrect') if res.code == 401

    if res.code == 200 && !res.body.empty?
      json_body = res.get_json_document
      if json_body.empty?
        vprint_error('Unable to parse JSON')
        return
      end
    end

    elastic_table = Rex::Text::Table.new(
      'Header' => 'Cluster Information',
      'Indent' => 2,
      'Columns' =>
      [
        'Cluster Name',
        'Status',
        'Number of Nodes'
      ]
    )

    elastic_table << [
      json_body['cluster_name'],
      json_body['status'],
      json_body['number_of_nodes']
    ]
    print_good(elastic_table.to_s)
  end

  def get_node_info
    vprint_status('Querying node information...')
    request = {
      'uri' => normalize_uri(target_uri.path, '_cat', 'nodes'),
      'method' => 'GET',
      'headers' => {
        'Accept' => 'application/json'
      },
      'vars_get' => {
        'h' => 'ip,port,version,http,uptime,name,heap.current,heap.max,ram.current,ram.max,node.role,master,cpu,disk.used,disk.total'
      }
    }
    request['authorization'] = basic_auth(datastore['USERNAME'], datastore['PASSWORD']) if datastore['USERNAME'] || datastore['PASSWORD']

    res = send_request_cgi(request)

    fail_with(Failure::Unreachable, "#{peer} - Could not connect to web service - no response") if res.nil?
    fail_with(Failure::NoAccess, 'Credentials required, or incorrect') if res.code == 401

    if res.code == 200 && !res.body.empty?
      json_body = res.get_json_document
      if json_body.empty?
        vprint_error('Unable to parse JSON')
        return
      end
    end

    elastic_table = Rex::Text::Table.new(
      'Header' => 'Node Information',
      'Indent' => 2,
      'Columns' =>
      [
        'IP',
        'Transport Port',
        'HTTP Port',
        'Version',
        'Name',
        'Uptime',
        'Ram Usage',
        'Node Role',
        'Master',
        'CPU Load',
        'Disk Usage'
      ]
    )
    json_body.each do |node|
      report_service(
        host: node['ip'],
        port: node['port'],
        proto: 'tcp',
        name: 'elasticsearch'
      )
      report_service(
        host: node['ip'],
        port: node['http'].split(':')[1],
        proto: 'tcp',
        name: 'elasticsearch'
      )
      elastic_table << [
        node['ip'],
        node['port'],
        node['http'],
        node['version'],
        node['name'],
        node['uptime'],
        "#{node['ram.current']}/#{node['ram.max']}",
        node['node.role'],
        node['master'],
        "#{node['cpu']}%",
        "#{node['disk.used']}/#{node['disk.total']}"
      ]
    end
    print_good(elastic_table.to_s)
  end

  def get_version_info
    vprint_status('Querying version information...')
    request = {
      'uri' => normalize_uri(target_uri.path),
      'method' => 'GET'
    }
    request['authorization'] = basic_auth(datastore['USERNAME'], datastore['PASSWORD']) if datastore['USERNAME'] || datastore['PASSWORD']

    res = send_request_cgi(request)

    fail_with(Failure::Unreachable, "#{peer} - Could not connect to web service - no response") if res.nil?
    fail_with(Failure::NoAccess, 'Credentials required, or incorrect') if res.code == 401

    # leaving this here for future travelers, this header was added in 7.14.0 https://www.elastic.co/guide/en/elasticsearch/reference/7.17/release-notes-7.14.0.html
    # so it isn't too reliable to check for
    # fail_with(Failure::Unreachable, "#{peer} - Elasticsearch not detected in X-elastic-product header") unless res.headers['X-elastic-product'] == 'Elasticsearch'

    if res.code == 200 && !res.body.empty?
      json_body = res.get_json_document
      if json_body.empty?
        vprint_error('Unable to parse JSON')
        return
      end
    end

    fail_with(Failure::Unreachable, "#{peer} - Elasticsearch cluster name not found, likely not Elasticsearch server") unless json_body['cluster_name']

    elastic_table = Rex::Text::Table.new(
      'Header' => 'Elastic Information',
      'Indent' => 2,
      'Columns' =>
      [
        'Name',
        'Cluster Name',
        'Version',
        'Build Type',
        'Lucene Version'
      ]
    )

    elastic_table << [
      json_body['name'],
      json_body['cluster_name'],
      json_body.dig('version', 'number'),
      json_body.dig('version', 'build_type'),
      json_body.dig('version', 'lucene_version'),
    ]
    print_good(elastic_table.to_s)

    @service = report_service(
      host: rhost,
      port: rport,
      proto: 'tcp',
      name: 'elasticsearch'
    )
  end

  def get_users
    vprint_status('Querying user information...')
    request = {
      'uri' => normalize_uri(target_uri.path, '_security', 'user/'),
      'method' => 'GET'
    }
    request['authorization'] = basic_auth(datastore['USERNAME'], datastore['PASSWORD']) if datastore['USERNAME'] || datastore['PASSWORD']

    res = send_request_cgi(request)

    fail_with(Failure::Unreachable, "#{peer} - Could not connect to web service - no response") if res.nil?
    fail_with(Failure::NoAccess, 'Credentials required, or incorrect') if res.code == 401

    if res.code == 200 && !res.body.empty?
      json_body = res.get_json_document
      if json_body.empty?
        vprint_error('Unable to parse JSON')
        return
      end
    end

    if json_body.nil?
      print_bad('Unable to pull user data')
      return
    end

    elastic_table = Rex::Text::Table.new(
      'Header' => 'User Information',
      'Indent' => 2,
      'Columns' =>
      [
        'Name',
        'Roles',
        'Email',
        'Metadata',
        'Enabled'
      ]
    )

    json_body.each do |username, attributes|
      elastic_table << [
        username,
        attributes['roles'],
        attributes['email'],
        attributes['metadata'],
        attributes['enabled'],
      ]
    end
    print_good(elastic_table.to_s)
  end

  def run
    get_version_info
    get_node_info
    get_cluster_info
    get_indices
    get_users
  end
end
