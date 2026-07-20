##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'uri'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Apple TV Video Remote Control',
        'Description' => %q{
          This module plays a video on an AppleTV device. Note that
          AppleTV can be somewhat picky about the server that hosts the video.
          Tested servers include default IIS, default Apache, and Ruby's WEBrick.
          For WEBrick, the default MIME list may need to be updated, depending on
          what media file is to be played. Python SimpleHTTPServer is not
          recommended. Also, if you're playing a video, the URL must be an IP
          address. Some AppleTV devices are actually password-protected; in that
          case please set the PASSWORD datastore option. For password
          brute forcing, please see the module auxiliary/scanner/http/appletv_login.
        },
        'Author' => [
          '0a29406d9794e4f9b30b3c5d6702c708', # Original work
          'sinn3r' # Make myself liable to mistakes since I made significant changes
        ],
        'References' => [
          ['URL', 'http://nto.github.io/AirPlay.html']
        ],
        'DefaultOptions' => { 'HttpUsername' => 'AirPlay' },
        'License' => MSF_LICENSE,
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS, SCREEN_EFFECTS],
          'Reliability' => []
        }
      )
    )

    register_options([
      Opt::RPORT(7000),
      OptInt.new('TIME', [true, 'Time in seconds to show the video', 60]),
      OptString.new('URL', [true, 'URL of video to show. Must use an IP address']),
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

  # Sends a video request to AppleTV device.
  #
  # @note HttpClient isn't used because we need to keep the connection alive
  #   so that the video can keep playing for the specified duration.
  #
  # @param opts [Hash] HTTP request options
  # @option opts [String] :method HTTP method (e.g., 'POST')
  # @option opts [String] :uri Request URI path
  # @option opts [Hash] :headers HTTP headers
  # @option opts [String] :data Request body data
  #
  # @return [Rex::Proto::Http::Response, nil] HTTP response object or nil on timeout
  def send_video_request(opts)
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

  # Validates the video source URI.
  #
  # @note AppleTV requires an IP address in the URL rather than a domain name.
  #
  # @param uri [String] Video source URI to validate
  #
  # @raise [Msf::OptionValidateError] if the URI host is not a valid IPv4 address
  #
  # @return [void]
  def validate_source!(uri)
    unless Rex::Socket.is_ipv4?(URI(uri).host)
      raise Msf::OptionValidateError, ['URL']
    end
  end

  # Plays a video on the AppleTV device.
  #
  # @return [void]
  def play_video_uri
    uri = datastore['URL']
    validate_source!(uri)

    body = "Content-Location: #{uri}\n"
    body << "Start-Position: 0.0\n"

    opts = {
      'method' => 'POST',
      'uri' => '/play',
      'headers' => {
        'Content-Length' => body.length.to_s,
        'Content-Type' => 'text/parameters'
      },
      'data' => body
    }

    res = send_video_request(opts)

    if !res
      print_status('The connection timed out')
    elsif res.code == 200
      print_status('Received HTTP 200')
    else
      print_error('The request failed due to an unknown reason')
    end
  end

  # Stops video playback (currently not implemented).
  #
  # @note The /stop API endpoint behavior is unclear. Thread management
  #   for stopping playback needs further investigation.
  #
  # @raise [NotImplementedError] This method is not yet implemented
  #
  # @return [void]
  def stop_play
    raise NotImplementedError
  end

  # Executes the module to play video on target AppleTV.
  #
  # @return [void]
  def run
    print_status("Video request sent. Duration set: #{datastore['TIME']} seconds")
    play_video_uri
  end
end
