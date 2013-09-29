##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::Ftp
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::AuthBrute

  def proto
    'ftp'
  end

  def initialize(info={})
    super(
        update_info(
            info,
            'Name'        => 'FTP Authentication Scanner',
            'Description' => %q{
              This module will test FTP logins on a range of machines and
              report successful logins.  If you have loaded a database plugin
              and connected to a database this module will record successful
              logins and hosts so you can track your access.
            },
            'Author'      => 'todb',
            'References'     =>
                [
                    [ 'CVE', '1999-0502'] # Weak password
                ],
            'License'     => MSF_LICENSE
        )
    )

    register_options(
      [
        Opt::RPORT(21),
        OptBool.new('RECORD_GUEST', [ false, "Record anonymous/guest logins to the database", false])
      ], self.class)

    register_advanced_options(
      [
        OptBool.new('SINGLE_SESSION', [ false, 'Disconnect after every login attempt', false])
      ]
    )

    deregister_options('FTPUSER','FTPPASS') # Can use these, but should use 'username' and 'password'
    @accepts_all_logins = {}
  end


  def run_host(ip)
    print_status("#{ip}:#{rport} - Starting FTP login sweep")
    if check_banner
      @@credentials_tried = {}
      if datastore['RECORD_GUEST'] == false and check_anonymous == :next_user
        @accepts_all_logins[@access] ||= []
        @accepts_all_logins[@access] << ip
        print_status("Successful authentication with #{@access.to_s} access on #{ip} will not be reported")
      end
      each_user_pass { |user, pass|
        next if user.nil?
        ret = do_login(user,pass)
        ftp_quit if datastore['SINGLE_SESSION']
        if ret == :next_user
          unless user == user.downcase
            ret = do_login(user.downcase,pass)
            if ret == :next_user
              user = user.downcase
              print_status("Username #{user} is not case sensitive")
            end
          end
          if datastore['RECORD_GUEST']
            report_ftp_creds(user,pass,@access)
          else
            if @accepts_all_logins[@access]
              report_ftp_creds(user,pass,@access) unless @accepts_all_logins[@access].include?(ip)
            else
              report_ftp_creds(user,pass,@access)
            end
          end
        end
        ret
      }
#			check_anonymous
    else
      return
    end
    ftp_quit
  end

  def ftp_quit
    begin
      send_quit if @ftp_sock
    rescue ::Rex::ConnectionError, EOFError, ::Errno::ECONNRESET
    end
    disconnect if @ftp_sock
    @ftp_sock = nil
  end

  # Always check for anonymous access by pretending to be a browser.
  def check_anonymous
    browser_passwords = {}
    browser_passwords['IE6'] = "IEUser@"
    browser_passwords['IE8'] = "User@"
    browser_passwords['Firefox'] = 'mozilla@example.com'
    browser_passwords['Chrome'] = 'chrome@example.com'
    unless @@credentials_tried.keys.include? "#{rhost}:#{rport}:anonymous"
      do_login("anonymous",browser_passwords.values[rand(browser_passwords.size)])
    end
  end

  def check_banner
    @ftp_sock = connect(true, false)
    if self.banner
      banner_sanitized = Rex::Text.to_hex_ascii(self.banner.to_s)
      print_status("#{rhost}:#{rport} - FTP Banner: '#{banner_sanitized}'")
      report_service(:host => rhost, :port => rport, :name => "ftp", :info => banner_sanitized)
      return true
    else
      print_error("#{rhost}:#{rport} - Did not get an FTP service banner")
      return false
    end
  end

  def do_login(user=nil,pass=nil)
    vprint_status("#{rhost}:#{rport} - Attempting FTP login for '#{user}':'#{pass}'")
    this_attempt ||= {}
    this_attempt[[user,pass]] ||= 0
    while this_attempt[[user,pass]] <= 3
      @ftp_sock = connect(true,false) unless @ftp_sock
      begin
        user_response = send_user(user, @ftp_sock)
        if user_response !~ /^(331|2)/
          vprint_error("#{rhost}:#{rport} - The server rejected username: '#{user}'")
          return :skip_user
        end
        pass_response = send_pass(pass, @ftp_sock)
        if pass_response =~ /^2/
          print_good("#{rhost}:#{rport} - Successful FTP login for '#{user}':'#{pass}'")
          @access = test_ftp_access(user)
          ftp_quit
          return :next_user
        else
          vprint_status("#{rhost}:#{rport} - Failed FTP login for '#{user}':'#{pass}'")
          return :fail
        end
      rescue ::Rex::ConnectionError, EOFError, ::Errno::ECONNRESET => e
        this_attempt[[user,pass]] += 1
        vprint_error "#{rhost}:#{rport} - Caught #{e.class}, reconnecting and retrying"
        disconnect
        @ftp_sock = nil
      end
    end
    return :connection_error
  end

  def test_ftp_access(user)
    dir = Rex::Text.rand_text_alpha(8)
    write_check = send_cmd(['MKD', dir], true)
    if write_check and write_check =~ /^2/
      send_cmd(['RMD',dir], true)
      print_status("#{rhost}:#{rport} - User '#{user}' has READ/WRITE access")
      return :write
    else
      print_status("#{rhost}:#{rport} - User '#{user}' has READ access")
      return :read
    end
  end

  def report_ftp_creds(user,pass,access)
    report_auth_info(
      :host => rhost,
      :port => rport,
      :sname => 'ftp',
      :user => user,
      :pass => pass,
      :type => "password#{access == :read ? "_ro" : "" }",
      :source_type => "user_supplied",
      :active => true
    )
  end

end
