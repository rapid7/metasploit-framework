##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary
  # Exploit mixins should be called first
  include Msf::Exploit::Remote::HttpClient
  # Scanner mixin should be near last
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'        => 'HTTP HTML Title Tag Content Grabber',
      'Description' => %q{
        Generates a GET request to the webservers provided and returns the server header,
        HTML title attribute and location header (if set). Useful for rapidly identifying
        interesting web applications en mass.
      },
      'Author'       => 'Stuart Morgan <stuart.morgan[at]mwrinfosecurity.com>',
      'License'     => MSF_LICENSE,
    )

    register_options(
      [
        OptBool.new('STORE_NOTES', [ true, 'Store the captured information in notes. Use "notes -t http.title" to view', true ]),
        OptBool.new('SHOW_ERRORS', [ true, 'Show error messages relating to grabbing titles on the console', true ]),
        OptBool.new('SHOW_TITLES', [ true, 'Show the titles on the console as they are grabbed', true ]),
        OptString.new('TARGETURI', [true, 'The base path', '/'])
      ], self.class)

    deregister_options('VHOST')
  end

  def run
    if datastore['STORE_NOTES'] == false && datastore['SHOW_ERRORS'] == false && datastore['SHOW_TITLES'] == false
      print_error("Notes storage is false, errors have been turned off and titles are not being shown on the console. There isn't much point in running this module.")
    else
      super
    end
  end

  def run_host(target_host)
    begin
        # Send a normal GET request
        res = send_request_cgi(
          'uri' => normalize_uri(target_uri.path)
        )

        # If no response, quit now
        if res.nil?
          print_error("[#{target_host}:#{rport}] No response") if datastore['SHOW_ERRORS'] == true
          return
        end

        # Retrieve the headers to capture the Location and Server header
        # Note that they are case-insensitive but stored in a hash
        server_header = nil
        location_header = nil
        if !res.headers.nil?
          res.headers.each do |key, val|
            location_header = val if key.downcase == 'location'
            server_header  = val if key.downcase == 'server'
          end
        else
          print_error("[#{target_host}:#{rport}] No HTTP headers") if datastore['SHOW_ERRORS'] == true
        end

        # If the body is blank, just stop now as there is no chance of a title
        if res.body.nil?
          print_error("[#{target_host}:#{rport}] No webpage body") if datastore['SHOW_ERRORS'] == true
          return
        end

        # Very basic, just match the first title tag we come to. If the match fails,
        # there is no chance that we will have a title
        rx = %r{<title>[\n\t\s]*(?<title>.+?)[\s\n\t]*</title>}im.match(res.body.to_s)
        unless rx
          print_error("[#{target_host}:#{rport}] No webpage title") if datastore['SHOW_ERRORS'] == true
          return
        end

        # Last bit of logic to capture the title
        rx[:title].strip!
        if rx[:title] != ''
          rx_title = Rex::Text.html_decode(rx[:title])
          print_status("[#{target_host}:#{rport}] [C:#{res.code}] [R:#{location_header}] [S:#{server_header}] #{rx_title}") if datastore['SHOW_TITLES'] == true
          if datastore['STORE_NOTES'] == true
            notedata = { code: res.code, port: rport, server: server_header, title: rx_title, redirect: location_header }
            report_note(host: target_host, type: "http.title", data: notedata)
          end
        else
          print_error("[#{target_host}:#{rport}] No webpage title") if datastore['SHOW_ERRORS'] == true
        end
      end

      rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
      rescue ::Timeout::Error, ::Errno::EPIPE
  end
end
