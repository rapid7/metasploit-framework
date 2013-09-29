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
  def initialize(info={})
    super(
        update_info(
            info,
            'Name'        => 'Joomla Version Scanner',
            'Description' => %q{
              This module scans a Joomla install for information about the underlying
              operating system and Joomla version.
            },
            'Author'      => [ 'newpid0' ],
            'License'     => MSF_LICENSE
        )
    )

    register_options(
      [
        OptString.new('TARGETURI', [ true,  "The path to the Joomla install", '/'])
      ], self.class)
  end

  def peer
    return "#{rhost}:#{rport}"
  end

  def os_fingerprint(response)
    if not response.headers.has_key?('Server')
      return "Unkown OS (No Server Header)"
    end

    case response.headers['Server']
    when /Win32/, /\(Windows/, /IIS/
      os = "Windows"
    when /Apache\//
      os = "*Nix"
    else
      os = "Unknown Server Header Reporting: "+response.headers['Server']
    end
    return os
  end

  def fingerprint(response)
    case response.body
    when /<version.*\/?>(.+)<\/version\/?>/i
      v = $1
      out = (v =~ /^6/) ? "Joomla #{v}" : " #{v}"
    when /system\.css 20196 2011\-01\-09 02\:40\:25Z ian/,
      /MooTools\.More\=\{version\:\"1\.3\.0\.1\"/,
      /en-GB\.ini 20196 2011\-01\-09 02\:40\:25Z ian/,
      /en-GB\.ini 20990 2011\-03\-18 16\:42\:30Z infograf768/,
      /20196 2011\-01\-09 02\:40\:25Z ian/
      out = "1.6"
    when /system\.css 21322 2011\-05\-11 01\:10\:29Z dextercowley /,
      /MooTools\.More\=\{version\:\"1\.3\.2\.1\"/,
      /22183 2011\-09\-30 09\:04\:32Z infograf768/,
      /21660 2011\-06\-23 13\:25\:32Z infograf768/
      out = "1.7"
    when /Joomla! 1.5/,
      /MooTools\=\{version\:\'1\.12\'\}/,
      /11391 2009\-01\-04 13\:35\:50Z ian/
      out = "1.5"
    when /Copyright \(C\) 2005 \- 2012 Open Source Matters/,
      /MooTools.More\=\{version\:\"1\.4\.0\.1\"/
      out = "2.5"
    when /<meta name=\"Keywords\" content=\"(.*)\">\s+<meta name/
      out = $1.split(/,/)[0]
    when /(Copyright \(C\) 2005 - 200(6|7))/,
      /47 2005\-09\-15 02\:55\:27Z rhuk/,
      /423 2005\-10\-09 18\:23\:50Z stingrey/,
      /1005 2005\-11\-13 17\:33\:59Z stingrey/,
      /1570 2005\-12\-29 05\:53\:33Z eddieajau/,
      /2368 2006\-02\-14 17\:40\:02Z stingrey/,
      /4085 2006\-06\-21 16\:03\:54Z stingrey/,
      /4756 2006\-08\-25 16\:07\:11Z stingrey/,
      /5973 2006\-12\-11 01\:26\:33Z robs/,
      /5975 2006\-12\-11 01\:26\:33Z robs/
      out = "1.0"
    else
      out = 'Unknown Joomla'
    end
    return out
  end

  def check_file(tpath, file, ip)
    res = send_request_cgi({
      'uri' => "#{tpath}#{file}",
      'method' => 'GET'
    })

    return :abort if res.nil?

    res.body.gsub!(/[\r|\n]/, ' ')

    if (res.code == 200)
      os = os_fingerprint(res)
      out = fingerprint(res)
      return false if not out

      if(out =~ /Unknown Joomla/)
        print_error("#{peer} - Unable to identify Joomla Version with #{file}")
        return false
      else
        print_good("#{peer} - Joomla Version:#{out} from: #{file} ")
        print_good("#{peer} - OS: #{os}")
        report_note(
          :host  => ip,
          :port  => datastore['RPORT'],
          :proto => 'http',
          :ntype => 'joomla_version',
          :data  => out
        )
        return true
      end
    elsif (res.code == 403)
      if(res.body =~ /secured with Secure Sockets Layer/ or res.body =~ /Secure Channel Required/ or res.body =~ /requires a secure connection/)
        vprint_status("#{ip} denied access to #{ip} (SSL Required)")
      elsif(res.body =~ /has a list of IP addresses that are not allowed/)
        vprint_status("#{ip} restricted access by IP")
      elsif(res.body =~ /SSL client certificate is required/)
        vprint_status("#{ip} requires a SSL client certificate")
      else
        vprint_status("#{ip} denied access to #{ip} #{res.code} #{res.message}")
      end
      return :abort
    end

    return false

  rescue OpenSSL::SSL::SSLError
    vprint_error("#{peer} - SSL error")
    return :abort
  rescue Errno::ENOPROTOOPT, Errno::ECONNRESET, ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::ArgumentError
    vprint_error("#{peer} - Unable to Connect")
    return :abort
  rescue ::Timeout::Error, ::Errno::EPIPE
    vprint_error("#{peer} - Timeout error")
    return :abort
  end

  def run_host(ip)
    tpath = normalize_uri(target_uri.path)
    if tpath[-1,1] != '/'
      tpath += '/'
    end

    files = [
      'language/en-GB/en-GB.xml',
      'templates/system/css/system.css',
      'media/system/js/mootools-more.js',
      'language/en-GB/en-GB.ini',
      'htaccess.txt',
      'language/en-GB/en-GB.com_media.ini'
    ]

    vprint_status("#{peer} - Checking Joomla version")
    files.each do |file|
      joomla_found = check_file(tpath, file, ip)
      return if joomla_found == :abort
      break if joomla_found
    end
  end

end
