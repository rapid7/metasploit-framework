##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'CouchDB Enum Utility',
      'Description'    => %q{
        Send a "send_request_cgi()" to enumerate databases and your values on CouchDB (Without authentication by default)
      },
      'Author'         => [ 'espreto <robertoespreto[at]gmail.com>' ],
      'License'        => MSF_LICENSE
      ))

    register_options(
      [
        Opt::RPORT(5984),
        OptString.new('TARGETURI', [true, 'Path to list all the databases', '/_all_dbs']),
        OptEnum.new('HTTP_METHOD', [true, 'HTTP Method, default GET', 'GET', ['GET', 'POST', 'PUT', 'DELETE'] ]),
        OptString.new('USERNAME', [false, 'The username to login as']),
        OptString.new('PASSWORD', [false, 'The password to login with'])
      ], self.class)
    end

  def run
    username = datastore['USERNAME']
    password = datastore['PASSWORD']

    uri = normalize_uri(target_uri.path)
    res = send_request_cgi({
      'uri'      => uri,
      'method'   => datastore['HTTP_METHOD'],
      'authorization' => basic_auth(username, password),
      'headers'  => {
        'Cookie'   => 'Whatever?'
      }
    })

    if res.nil?
      print_error("No response for #{target_host}")
      return nil
    end

    begin
      temp = JSON.parse(res.body)
    rescue JSON::ParserError
      print_error("Unable to parse JSON")
      return
    end

    results = JSON.pretty_generate(temp)

    if (res.code == 200)
      print_good("#{target_host}:#{rport} -> #{res.code}")
      print_good("Response Headers:\n\n #{res.headers}")
      print_good("Response Body:\n\n #{results}\n")
    elsif (res.code == 403) # Forbidden
      print_error("Received #{res.code} - Forbidden to #{target_host}:#{rport}")
      print_error("Response from server:\n\n #{results}\n")
    elsif (res.code == 404) # Not Found
      print_error("Received #{res.code} - Not Found to #{target_host}:#{rport}")
      print_error("Response from server:\n\n #{results}\n")
    else
      print_status("Received #{res.code}")
      print_line("#{results}")
    end

    if res and res.code == 200 and res.headers['Content-Type'] and res.body.length > 0
      path = store_loot("couchdb.enum.file", "text/plain", rhost, res.body, "CouchDB Enum Results")
      print_status("Results saved to #{path}")
    else
      print_error("Failed to save the result")
    end
  end
end
