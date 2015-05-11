##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'cgi'

class Metasploit3 < Msf::Auxiliary
  # Exploit mixins should be called first
  include Msf::Exploit::Remote::HttpClient
  # Scanner mixin should be near last
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'        => 'HTTP HTML <title> tag content grabber',
      'Description' => 'Generates a GET request to the webservers provided and returns the server header, HTML title attribute and location header (if set). Useful for rapidly identifying all webservers on a network and identifying interesting hosts en mass.',
      'Author'       => ['Stuart Morgan <stuart.morgan[at]mwrinfosecurity.com>'],
      'License'     => MSF_LICENSE,
    )

    register_options(
      [
        OptBool.new('STORE_NOTES', [ true, 'Store the captured information in notes. Use "notes -t http.title" to view', true ]),
        OptBool.new('SHOW_ERRORS', [ true, 'Show error messages relating to grabbing titles on the console', true ]),
        OptBool.new('SHOW_TITLES', [ true, 'Show the titles on the console as they are grabbed', true ])
      ], self.class)

    deregister_options('VHOST')
  end

  def run

    if datastore['STORE_NOTES']==false && datastore['SHOW_ERRORS']==false && datastore['SHOW_TITLES']==false
        print_error("Notes storage is false, errors have been turned off and titles are not being shown on the console. There isn't much point in running this module.")
    else
        super
    end
  end

  def run_host(target_host)
    begin
      res = send_request_cgi('uri'          => '/',
                             'method'       => 'GET')

      if res.nil?
        print_error("No response from #{target_host}:#{rport}") if datastore['SHOW_ERRORS'] == true
      else
        server_header = nil
        location_header = nil
        if !res.headers.nil?
          res.headers.each do |key, val|
            location_header = val if key.downcase == 'location'
            server_header  = val if key.downcase == 'server'
          end
        else
          print_error("No headers from #{target_host}:#{rport}") if datastore['SHOW_ERRORS'] == true
        end

        if !res.body.nil?
          # Very basic, just match the first title tag we come to.
          rx = %r{<title>[\n\t\s]*(?<title>.+?)[\s\n\t]*</title>}im.match(res.body.to_s)
          if rx
            rx[:title].strip!
            if rx[:title] != ''
              rx_title = CGI.unescapeHTML(rx[:title])
              print_status("[#{target_host}:#{rport}] [C:#{res.code}] [R:#{location_header}] [S:#{server_header}] #{rx_title}") if datastore['SHOW_TITLES'] == true
              if datastore['STORE_NOTES'] == true
                notedata = { code: res.code, port: rport, server: server_header, title: rx_title, redirect: location_header }
                report_note(host: target_host, type: "http.title", data: notedata)
              end
            else
              print_error("No webpage title from #{target_host}:#{rport}") if datastore['SHOW_ERRORS'] == true
            end
          else
            print_error("No webpage title from #{target_host}:#{rport}") if datastore['SHOW_ERRORS'] == true
          end
        else
          print_error("No webpage body from #{target_host}:#{rport}") if datastore['SHOW_ERRORS'] == true
        end
      end

      rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
      rescue ::Timeout::Error, ::Errno::EPIPE
    end
  end
end
