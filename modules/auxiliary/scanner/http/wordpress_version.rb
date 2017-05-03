##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
#   http://metasploit.com/framework/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'           => "Wordpress Version Scanner",
      'Description'    => %q{
          This module scans a Wordpress install for information about the underlying
        operating system and Wordpress version.
      },
      'Author'         => ['0pc0deFR'],
      'License'        => MSF_LICENSE
    ))

    register_options(
      [
	OptString.new('TARGETURI', [ true,  "The path to the Wordpress install", '/']),
        Opt::RPORT(80)
      ], self.class)
  end

  def fingerprint_version(response)
    case response.body
    when /WordPress 3.3.1/
      out = "3.3.1"
    when /WordPress 3.5/
      out = "3.5"
    when /WordPress 3.5.1/
      out = "3.5.1"
    when /WordPress 3.5.2/
      out = "3.5.2"
    when /WordPress 3.6/
      out = "3.6"
    when /WordPress 3.6.1/
      out = "3.6.1"
    when /WordPress 3.7/
      out = "3.7"
    when /WordPress 3.7.1/
      out = "3.7.1"
    else
      out = 'Unknown Wordpress'
    end
    return out
  end

  def check_wordpress(tpath)
    res = send_request_cgi({
      'uri' => "#{tpath}/wp-includes/wlwmanifest.xml",
      'method' => 'GET'
    })
    return false if res.nil?

    if (res.code == 200)
      case res.body
      when /blog-postapi-url/
        return true
      else
        return false
      end
    end
  end

  def check_file(tpath)
    res = send_request_cgi({
      'uri' => "#{tpath}",
      'method' => 'GET'
    })
    return false if res.nil?

    res.body.gsub!(/[\r|\n]/, ' ')
    if (res.code == 200)
      out = fingerprint_version(res)
      return false if not out

      if(out =~ /Unknown Wordpress/)
        print_error("#{peer} - Unable to identify Wordpress Version")
        return false
      else
        print_good("#{peer} - Wordpress Version: #{out}")
        return true
      end
    end
    return false
  end

  def run_host(ip)
    tpath = normalize_uri(target_uri.path)
    if tpath[-1,1] != '/'
      tpath += '/'
    end
    detect_wordpress = check_wordpress(tpath)
    if(detect_wordpress == true)
      print_good "Wordpress detected"
      vprint_status("#{peer} - Checking Wordpress version")
      check_file(tpath)
    end
  end
end
