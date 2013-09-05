##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(update_info(info,
      'Name' => 'Wordpress Pingback Locator',
      'Description' => %q{
          This module will scan for wordpress sites with the Pingback
          API enabled. By interfacing with the API an attacker can cause
          the wordpress site to port scan an external target and return
          results. Refer to the wordpress_pingback_portscanner module.
          This issue was fixed in wordpress 3.5.1
        },
      'Author' =>
        [
          'Thomas McCarthy "smilingraccoon" <smilingraccoon[at]gmail.com>',
          'Brandon McCann "zeknox" <bmccann[at]accuvant.com>' ,
          'Christian Mehlmauer "FireFart" <FireFart[at]gmail.com>' # Original PoC
        ],
      'License' => MSF_LICENSE,
      'References'  =>
        [
          [ 'URL', 'http://www.securityfocus.com/archive/1/525045/30/30/threaded'],
          [ 'URL', 'http://www.ethicalhack3r.co.uk/security/introduction-to-the-wordpress-xml-rpc-api/'],
          [ 'URL', 'https://github.com/FireFart/WordpressPingbackPortScanner']
        ]
      ))

      register_options(
        [
          OptString.new('TARGETURI', [ true, 'The path to wordpress installation (e.g. /wordpress/)', '/'])
        ], self.class)

      register_advanced_options(
        [
          OptInt.new('NUM_REDIRECTS', [ true, "Number of HTTP redirects to follow", 10])
        ], self.class)
  end

  def setup()
    # Check if database is active
    if db()
      @db_active = true
    else
      @db_active = false
    end
  end

  def get_xml_rpc_url(ip)
    # code to find the xmlrpc url when passed in IP
    vprint_status("#{ip} - Enumerating XML-RPC URI...")

    begin

      uri = target_uri.path
      uri << '/' if uri[-1,1] != '/'

      res = send_request_cgi(
      {
          'method'	=> 'HEAD',
          'uri'		=> "#{uri}"
      })
      # Check if X-Pingback exists and return value
      if res
        if res['X-Pingback']
          return res['X-Pingback']
        else
          vprint_status("#{ip} - X-Pingback header not found")
          return nil
        end
      else
        return nil
      end
    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
      vprint_error("#{ip} - Unable to connect")
      return nil
    rescue ::Timeout::Error, ::Errno::EPIPE
      vprint_error("#{ip} - Unable to connect")
      return nil
    end
  end

  # Creates the XML data to be sent
  def generate_pingback_xml(target, valid_blog_post)
    xml = "<?xml version=\"1.0\" encoding=\"iso-8859-1\"?>"
    xml << "<methodCall>"
    xml << "<methodName>pingback.ping</methodName>"
    xml << "<params>"
    xml << "<param><value><string>#{target}</string></value></param>"
    xml << "<param><value><string>#{valid_blog_post}</string></value></param>"
    xml << "</params>"
    xml << "</methodCall>"
    return xml
  end

  def get_blog_posts(xml_rpc, ip)
    # find all blog posts within IP and determine if pingback is enabled
    vprint_status("#{ip} - Enumerating Blog posts on...")
    blog_posts = nil

    uri = target_uri.path
    uri << '/' if uri[-1,1] != '/'

    # make http request to feed url
    begin
      vprint_status("#{ip} - Resolving #{uri}?feed=rss2 to locate wordpress feed...")
      res = send_request_cgi({
        'uri'    => "#{uri}?feed=rss2",
        'method' => 'GET'
        })

      count = datastore['NUM_REDIRECTS']

      # Follow redirects
      while (res.code == 301 || res.code == 302) and res.headers['Location'] and count != 0
        vprint_status("#{ip} - Web server returned a #{res.code}...following to #{res.headers['Location']}")

        uri = res.headers['Location'].sub(/(http|https):\/\/.*?\//, "/")
        res = send_request_cgi({
          'uri'    => "#{uri}",
          'method' => 'GET'
          })

        if res.code == 200
          vprint_status("#{ip} - Feed located at #{uri}")
        else
          vprint_status("#{ip} - Returned a #{res.code}...")
        end
        count = count - 1
      end
    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
      vprint_error("#{ip} - Unable to connect")
      return nil
    rescue ::Timeout::Error, ::Errno::EPIPE
      vprint_error("#{ip} - Unable to connect")
      return nil
    end

    if res.nil? or res.code != 200
      vprint_status("#{ip} - Did not recieve HTTP response from #{ip}")
      return blog_posts
    end

    # parse out links and place in array
    links = res.body.scan(/<link>([^<]+)<\/link>/i)

    if links.nil? or links.empty?
      vprint_status("#{ip} - Feed at #{ip} did not have any links present")
      return blog_posts
    end

    links.each do |link|
      blog_post = link[0]
      pingback_response = get_pingback_request(xml_rpc, 'http://127.0.0.1', blog_post)
      if pingback_response
        pingback_disabled_match = pingback_response.body.match(/<value><int>33<\/int><\/value>/i)
        if pingback_response.code == 200 and pingback_disabled_match.nil?
          print_good("#{ip} - Pingback enabled: #{link.join}")
          blog_posts = link.join
          return blog_posts
        else
          vprint_status("#{ip} - Pingback disabled: #{link.join}")
        end
      end
    end
    return blog_posts
  end

  # method to send xml-rpc requests
  def get_pingback_request(xml_rpc, target, blog_post)
    uri = xml_rpc.sub(/.*?#{target}/,"")
    # create xml pingback request
    pingback_xml = generate_pingback_xml(target, blog_post)

    # Send post request with crafted XML as data
    begin
      res = send_request_cgi({
        'uri'    => "#{uri}",
        'method' => 'POST',
        'data'	 => "#{pingback_xml}"
        })
    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
      vprint_error("Unable to connect to #{uri}")
      return nil
    rescue ::Timeout::Error, ::Errno::EPIPE
      vprint_error("Unable to connect to #{uri}")
      return nil
    end
    return res
  end

  # Save data to vuln table
  def store_vuln(ip, blog)
    report_vuln(
      :host		=> ip,
      :proto		=> 'tcp',
      :port		=> datastore['RPORT'],
      :name		=> self.name,
      :info		=> "Module #{self.fullname} found pingback at #{blog}",
      :sname		=> datastore['SSL'] ? "https" : "http"
    )
  end

  # main control method
  def run_host(ip)
    # call method to get xmlrpc url
    xmlrpc = get_xml_rpc_url(ip)

    # once xmlrpc url is found, get_blog_posts
    if xmlrpc.nil?
      vprint_error("#{ip} - It doesn't appear to be vulnerable")
    else
      hash = get_blog_posts(xmlrpc, ip)

      if hash
        store_vuln(ip, hash) if @db_active
      else
        vprint_status("#{ip} - X-Pingback enabled but no vulnerable blogs found")
      end
    end
  end
end
