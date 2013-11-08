##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
#  http://metasploit.com/framework/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner
  include Msf::Exploit::Remote::Tcp

  def initialize(info = {})
    super(update_info(info,
      'Name' => 'Bing URL Enumerator',
      'Description' => %q{
        This module uses Bing to enumerate URLs from a specified range of IP addresses.
      },
      'Author' => [ 'Royce Davis <royce.davis[at]cliftonlarsonallen.com>' ],
      'License' => MSF_LICENSE
    ))
  
    deregister_options('RHOST','RPORT','VHOST')
  end

  def cleanup
    datastore['RHOST'] = @old_rhost
    datastore['RPORT'] = @old_rport
  end

  def run_host(ip)
    urls = []
    @old_rhost = datastore['RHOST']
    @old_rport = datastore['RPORT']

    datastore['RHOST'] = 'www.bing.com'
    datastore['RPORT'] = 80

    # We cannot use HttpClient to send a query to bing.com,
    # because there is a bug in get_once that keeps bailing on us before finishing
    # getting the data. get_once is the actual function used to receive HTTP data
    # for send_request_cgi().  See the following ticket for details:
    # http://dev.metasploit.com/redmine/issues/6499#note-11
    connect
    req = %Q|GET /search?q=ip:#{ip} HTTP/1.1\nHost: #{datastore['RHOST']}\nAccept: */*\n
    |

    req = req.gsub(/^\t\t/, '')
    sock.put(req)
    res = sock.get(-1, 1)
    m = res.to_s.scan(/(<cite>[a-z0-9]+(?:[\-\.])[a-z0-9]+(?:[\-\.])[a-z]{3,5})/)

    if m.empty?
      print_error("No matches found for #{ip}")
      return
    end

    m.each do |url|
      url = url.to_s.gsub(/<cite>/, '')

      # The URL returns in the following format:
      # ["www.example.com"]
      if url =~ /\[\"(.+)\"\]/
        urls << $1
        print_status("#{ip} = #{$1}")
      end
    end

    unless urls.empty?
      report_note(
        :host => ip,
        :data => urls,
        :type => 'URL'
      )
    end
  end
end
