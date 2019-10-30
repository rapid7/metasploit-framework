##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'F5 Networks Devices Management Interface Scanner',
      'Description'   => %q{
        This module scans for web management interfaces of the following F5 Networks devices:
        BigIP, BigIQ, Enterprise Manager, ARX, and FirePass.
      },
      'License'       => MSF_LICENSE,
      'Author'        =>
        [
          'Denis Kolegov <dnkolegov[at]gmail.com>',
          'Oleg Broslavsky <ovbroslavsky[at]gmail.com>',
          'Nikita Oleksov <neoleksov[at]gmail.com>'
        ],
      'DefaultOptions' =>
        {
          'SSL' => true,
          'RPORT' => 443
        }
    ))

    register_options(
      [
        OptInt.new('TIMEOUT', [true, 'HTTPS connect/read timeout in seconds', 1])
      ])
  end

  def port_open?
    begin
      res = send_request_raw({'method' => 'GET', 'uri' => '/'}, datastore['TIMEOUT'])
      return true if res
    rescue ::Rex::ConnectionRefused
      vprint_status("Connection refused")
      return false
    rescue ::Rex::ConnectionError
      vprint_error("Connection failed")
      return false
    rescue ::OpenSSL::SSL::SSLError
      vprint_error("SSL/TLS connection error")
      return false
    end
  end

  def run_host(ip)
    return unless port_open?

    res = send_request_raw('method' => 'GET', 'uri' => '/')
    if res && res.code == 200

      # Detect BigIP management interface
      if res.body =~ /<title>BIG\-IP/
        print_good("F5 BigIP web management interface found")
        return
      end

      # Detect EM management interface
      if res.body =~ /<title>Enterprise Manager/
        print_good("F5 Enterprise Manager web management interface found")
        return
      end

      # Detect ARX management interface
      if res.body =~ /<title>F5 ARX Manager Login<\/title>/
        print_good("ARX web management interface found")
        return
      end
    end

    # Detect BigIQ management interface
    res = send_request_raw('method' => 'GET', 'uri' => '/ui/login/')
    if res && res.code == 200 && res.body =~ /<title>BIG\-IQ/
      print_good("F5 BigIQ web management interface found")
      return
    end

    # Detect FirePass management interface
    res = send_request_raw('method' => 'GET', 'uri' => '/admin/', 'rport' => rport)
    if res && res.code == 200 && res.body =~ /<br><br><br><big><b>&nbsp;FirePass/
      print_good("F5 FirePass web management interface found")
      return
    end
  end
end
