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
      'Name'        => 'Joomla Plugins Scanner',
      'Description' => %q{
          This module scans a Joomla install for plugins and potential
        vulnerabilities.
      },
      'Author'      => [ 'newpid0' ],
      'License'     => MSF_LICENSE
    )
    register_options(
      [
        OptString.new('TARGETURI', [ true,  "The path to the Joomla install", '/']),
        OptPath.new('PLUGINS',   [ true, "Path to list of plugins to enumerate", File.join(Msf::Config.install_root, "data", "wordlists", "joomla.txt")])
      ], self.class)
  end

  def peer
    return "#{rhost}:#{rport}"
  end

  def run_host(ip)
    tpath = normalize_uri(target_uri.path)
    if tpath[-1,1] != '/'
      tpath += '/'
    end

    vprint_status("#{peer} - Checking for interesting plugins")
    res = send_request_cgi({
      'uri' => tpath,
      'method' => 'GET'
    })
    return if res.nil?

    res.body.gsub!(/[\r|\n]/, ' ')
    File.open(datastore['PLUGINS'], 'rb').each_line do |line|
      papp = line.chomp
      plugin_search(tpath, papp, ip, res.body.size)
    end
  end

  def plugin_search(tpath, papp, ip, osize)
    res = send_request_cgi({
      'uri' => "#{tpath}#{papp}",
      'method' => 'GET'
    })
    return if res.nil?

    res.body.gsub!(/[\r|\n]/, ' ')
    nsize = res.body.size

    if (res.code == 200 and res.body !~/#404 Component not found/ and res.body !~/<h1>Joomla! Administration Login<\/h1>/ and osize != nsize)
      print_good("#{peer} - Plugin: #{tpath}#{papp} ")
      report_note(
        :host  => ip,
        :port  => rport,
        :proto => 'http',
        :ntype => 'joomla_plugin',
        :data  => "#{tpath}#{papp}",
        :update => :unique_data
      )

      if (papp =~/passwd/ and res.body =~/root/)
        print_good("#{peer} - Vulnerability: Potential LFI")
        report_web_vuln(
          :host	=> ip,
          :port	=> rport,
          :vhost  => vhost,
          :ssl    => ssl,
          :path	=> tpath,
          :method => "GET",
          :pname  => "",
          :proof  => "Response with code #{res.code} contains the 'root' signature",
          :risk   => 1,
          :confidence   => 10,
          :category     => 'Local File Inclusion',
          :description  => "Joomla: Potential LFI at #{tpath}#{papp}",
          :name   => 'Local File Inclusion'
        )
      elsif (res.body =~/SQL syntax/)
        print_good("#{peer} - Vulnerability: Potential SQL Injection")
        report_web_vuln(
          :host	=> ip,
          :port	=> rport,
          :vhost  => vhost,
          :ssl    => ssl,
          :path	=> tpath,
          :method => "GET",
          :pname  => "",
          :proof  => "Response with code #{res.code} contains the 'SQL syntax' signature",
          :risk   => 1,
          :confidence   => 10,
          :category     => 'SQL Injection',
          :description  => "Joomla: Potential SQLI at #{tpath}#{papp}",
          :name   => 'SQL Injection'
        )
      elsif (papp =~/>alert/ and res.body =~/>alert/)
        print_good("#{peer} - Vulnerability: Potential XSS")
        report_web_vuln(
          :host	=> ip,
          :port	=> rport,
          :vhost  => vhost,
          :ssl    => ssl,
          :path	=> tpath,
          :method => "GET",
          :pname  => "",
          :proof  => "Response with code #{res.code} contains the '>alert' signature",
          :risk   => 1,
          :confidence   => 10,
          :category     => 'Cross Site Scripting',
          :description  => "Joomla: Potential XSS at #{tpath}#{papp}",
          :name   => 'Cross Site Scripting'
        )
      elsif (papp =~/com_/)
        vars = papp.split('_')
        pages = vars[1].gsub('/','')
        res1 = send_request_cgi({
          'uri' => "#{tpath}index.php?option=com_#{pages}",
          'method' => 'GET'
        })
        if (res1.code == 200)
          print_good("#{peer} - Page: #{tpath}index.php?option=com_#{pages}")
          report_note(
            :host  => ip,
            :port  => datastore['RPORT'],
            :proto => 'http',
            :ntype => 'joomla_page',
            :data  => "Page: #{tpath}index.php?option=com_#{pages}",
            :update => :unique_data
          )
        else
          vprint_error("#{peer} - Page: #{tpath}index.php?option=com_#{pages} gave a #{res1.code} response")
        end
      end
    elsif (res.code == 403)
      if (res.body =~ /secured with Secure Sockets Layer/ or res.body =~ /Secure Channel Required/ or res.body =~ /requires a secure connection/)
        vprint_status("#{ip} ip access to #{ip} (SSL Required)")
      elsif (res.body =~ /has a list of IP addresses that are not allowed/)
        vprint_status("#{ip} restricted access by IP")
      elsif (res.body =~ /SSL client certificate is required/)
        vprint_status("#{ip} requires a SSL client certificate")
      else
        vprint_status("#{ip} denied access to #{ip}#{tpath}#{papp} - #{res.code} #{res.message}")
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
