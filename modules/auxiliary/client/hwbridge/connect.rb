##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Hardware Bridge Session Connector',
        'Description' => %q{
          The Hardware Bridge (HWBridge) is a standardized method for
          Metasploit to interact with Hardware Devices.  This extends
          the normal exploit capabilities to the non-ethernet realm and
          enables direct hardware and alternative bus manipulations.  You
          must have compatible bridging hardware attached to this machine or
          reachable on your network to use any HWBridge exploits.

          Use this exploit module to connect the physical HWBridge which
          will start an interactive hwbridge session.  You can launch a hwbridge
          server locally by using compliant hardware and executing the local_hwbridge
          module.  After that module has started, pass the HWBRIDGE_BASE_URL
          options to this connector module.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'Craig Smith' # hwbridge metasploit module
        ],
        'Session' => Msf::Sessions::HWBridge,
        'SessionTypes' => [ 'hwbridge' ],
        'References' => [
          [ 'URL', 'https://web.archive.org/web/20170206145056/http://opengarages.org/hwbridge/' ],
        ],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [],
          'Reliability' => []
        }
      )
    )
    register_options(
      [
        Opt::RPORT(8080),
        Opt::RHOST('127.0.0.1'),
        OptBool.new('DEBUGJSON', [false, 'Additional debugging out for JSON requests to HW Bridge', false]),
        OptString.new('TARGETURI', [ true, 'The path to the hwbridge API', '/'])
      ]
    )
    @last_access = nil
  end

  #
  # Generic fetch json call. returns hash of json
  #
  def fetch_json(uri)
    tpath = normalize_uri("#{datastore['TARGETURI']}/#{uri}")
    res = send_request_cgi({
      'uri' => tpath,
      'method' => 'GET'
    })
    return if !res || !res.body || !res.code

    if res.code == 401
      print_error "Access Denied: #{res.body}"
      return
    end

    if res.code == 200
      print_status res.body if datastore['DEBUGJSON'] == true
      return JSON.parse(res.body)
    end

    return
  rescue OpenSSL::SSL::SSLError
    vprint_error('SSL error')
    return
  rescue Errno::ENOPROTOOPT, Errno::ECONNRESET, ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::ArgumentError
    vprint_error('Unable to Connect')
    return
  rescue ::Timeout::Error, ::Errno::EPIPE
    vprint_error('Timeout error')
    return
  end

  #
  # Disclaimer for legal and those without common sense...
  #
  def print_disclaimer
    print_warning('NOTICE:  You are about to leave the matrix.  All actions performed on this hardware bridge')
    print_warning('         could have real world consequences.  Use this module in a controlled testing')
    print_warning('         environment and with equipment you are authorized to perform testing on.')
  end

  #
  # Uses status information to automatically load proper extensions
  #
  def autoload_extensions(sess)
    if hw_specialty.key?('automotive') && hw_specialty['automotive'] == (true)
      sess.load_automotive
    end
    if hw_specialty.key?('zigbee') && hw_specialty['zigbee'] == (true)
      sess.load_zigbee
    end
    if hw_specialty.key?('rftransceiver') && hw_specialty['rftransceiver'] == (true)
      sess.load_rftransceiver
    end
    sess.api_version = api_version if api_version
    sess.fw_version = fw_version if fw_version
    sess.hw_version = hw_version if hw_version
    sess.device_name = device_name if device_name
  end

  #
  # If the hardware contains custom methods, create functions for those
  #
  def load_custom_methods(sess)
    if hw_capabilities.key?('custom_methods') && hw_capabilities['custom_methods'] == (true)
      sess.load_custom_methods
    end
  end

  #
  # Fetches the status of the hwbridge
  #
  def get_status
    data = fetch_json('/status')
    return if data.nil?

    return unless data.key?('operational')

    @last_access = Time.now

    if data.key? 'hw_specialty'
      self.hw_specialty = data['hw_specialty']
    end
    if data.key? 'hw_capabilities'
      self.hw_capabilities = data['hw_capabilities']
    end
    if data.key? 'api_version'
      self.api_version = data['api_version']
    end
    if data.key? 'fw_version'
      self.fw_version = data['fw_version']
    end
    if data.key? 'hw_version'
      self.hw_version = data['hw_version']
    end
    if data.key? 'device_name'
      self.device_name = data['device_name']
    end
  end

  def run
    print_status("Attempting to connect to #{datastore['RHOST']}...")
    get_status

    if @last_access.nil?
      print_error 'Could not connect to API'
      return
    end

    sess = Msf::Sessions::HWBridge.new(self)
    sess.set_from_exploit(self)

    framework.sessions.register(sess)
    print_good('HWBridge session established')
    autoload_extensions(sess)
    load_custom_methods(sess)
    print_status "HW Specialty: #{hw_specialty}  Capabilities: #{hw_capabilities}"
    print_disclaimer
  end

  attr_reader :hw_specialty, :hw_capabilities, :api_version, :fw_version, :hw_version, :device_name

  protected

  attr_writer :hw_specialty, :hw_capabilities, :api_version, :fw_version, :hw_version, :device_name
end
