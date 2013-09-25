##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##
require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  # Huge thanks to @zeroSteiner for helping me. Also thanks to @kaospunk. Finally thanks to
  # Joomscan and various MSF modules for code examples.
  def initialize
    super(
      'Name'        => 'Joomla Page Scanner',
      'Description' => %q{
        This module scans a Joomla install for common pages.
      },
      'Author'      => [ 'newpid0' ],
      'License'     => MSF_LICENSE
    )
    register_options(
      [
        OptString.new('TARGETURI', [ true,  "The path to the Joomla install", '/'])
      ], self.class)
  end

  def run_host(ip)
    tpath = normalize_uri(target_uri.path)
    if tpath[-1,1] != '/'
      tpath += '/'
    end

    pages = [
      'robots.txt',
      'administrator/index.php',
      'admin/',
      'index.php/using-joomla/extensions/components/users-component/registration-form',
      'index.php/component/users/?view=registration',
      'htaccess.txt'
    ]

    vprint_status("#{peer} - Checking for interesting pages")
    pages.each do |page|
      scan_pages(tpath, page, ip)
    end

  end

  def scan_pages(tpath, page, ip)
    res = send_request_cgi({
      'uri' => "#{tpath}#{page}",
      'method' => 'GET',
    })
    return if not res or not res.body or not res.code
    res.body.gsub!(/[\r|\n]/, ' ')

    if (res.code == 200)
      note = "Page Found"
      if (res.body =~ /Administration Login/ and res.body =~ /\(\'form-login\'\)\.submit/ or res.body =~/administration console/)
        note = "Administrator Login Page"
      elsif (res.body =~/Registration/ and res.body =~/class="validate">Register<\/button>/)
        note = "Registration Page"
      end

      print_good("#{peer} - #{note}: #{tpath}#{page}")

      report_note(
        :host  => ip,
        :port  => datastore['RPORT'],
        :proto => 'http',
        :ntype => 'joomla_page',
        :data  => "#{note}: #{tpath}#{page}",
        :update => :unique_data
      )
    elsif (res.code == 403)
      if (res.body =~ /secured with Secure Sockets Layer/ or res.body =~ /Secure Channel Required/ or res.body =~ /requires a secure connection/)
        vprint_status("#{ip} denied access to #{ip} (SSL Required)")
      elsif (res.body =~ /has a list of IP addresses that are not allowed/)
        vprint_status("#{ip} restricted access by IP")
      elsif (res.body =~ /SSL client certificate is required/)
        vprint_status("#{ip} requires a SSL client certificate")
      else
        vprint_status("#{ip} ip access to #{ip} #{res.code} #{res.message}")
      end
    end

    return

    rescue OpenSSL::SSL::SSLError
      vprint_error("#{peer} - SSL error")
      return
    rescue Errno::ENOPROTOOPT, Errno::ECONNRESET, ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::ArgumentError
      vprint_error("#{peer} - Unable to Connect")
      return
    rescue ::Timeout::Error, ::Errno::EPIPE
      vprint_error("#{peer} - Timeout error")
      return
  end

end
