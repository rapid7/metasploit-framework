##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/base/sessions/hwbridge'

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HttpClient


  def initialize(info={})
    super( update_info( info, {
        'Name'          => 'Hardware Bridge Session Connector',
        'Description'   => %q{
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
        'License'       => MSF_LICENSE,
        'Author'        =>
          [
            'Craig Smith'                       # hwbridge metaspliot module
          ],
        'Session'       => Msf::Sessions::HWBridge,
        'SessionTypes'  => [ 'hwbridge' ],
        'References'    =>
          [
            [ 'URL', 'http://opengarages.org/hwbridge' ]  # TODO
          ]
      }
      ))
    register_options(
      [
        Opt::RPORT(8080),
        Opt::RHOST('127.0.0.1'),
        OptBool.new('DEBUGJSON', [false, "Additional debugging out for JSON requests to HW Bridge", false]),
        OptString.new('TARGETURI', [ true, "The path to the hwbridge API", '/'])
      ],
      self.class
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
    return nil if !res || !res.body || !res.code
    if res.code == 200
      print_status res.body if datastore['DEBUGJSON'] == true
      return JSON.parse(res.body)
    elsif res.code == 401
      print_error "Access Denied: #{res.body}"
    end
    return nil

    rescue OpenSSL::SSL::SSLError
      vprint_error("SSL error")
      return nil
    rescue Errno::ENOPROTOOPT, Errno::ECONNRESET, ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::ArgumentError
      vprint_error("Unable to Connect")
      return nil
    rescue ::Timeout::Error, ::Errno::EPIPE
      vprint_error("Timeout error")
      return nil

  end

  #
  # Disclaimer for legal and those without common sense...
  #
  def print_disclaimer
    print_warning("NOTICE:  You are about to leave the matrix.  All actions performed on this hardware bridge")
    print_warning("         could have real world consequences.  Use this module in a controlled testing")
    print_warning("         environment and with equipment you are authorized to perform testing on.")
  end

  #
  # Uses status information to automatically load proper extensions
  #
  def autoload_extensions(sess)
    if self.hw_specialty.key? 'automotive'
      sess.load_automotive if self.hw_specialty['automotive'] == true
    end
    if self.hw_specialty.has_key? 'zigbee'
      sess.load_zigbee if self.hw_specialty['zigbee'] == true
    end
    if self.hw_specialty.has_key? 'rftransceiver'
      sess.load_rftransceiver if self.hw_specialty['rftransceiver'] == true
    end
    sess.api_version = self.api_version if self.api_version
    sess.fw_version = self.fw_version if self.fw_version
    sess.hw_version = self.hw_version if self.hw_version
    sess.device_name = self.device_name if self.device_name
  end

  #
  # If the hardware contains custom methods, create functions for those
  #
  def load_custom_methods(sess)
    if self.hw_capabilities.key? 'custom_methods'
      sess.load_custom_methods if self.hw_capabilities['custom_methods'] == true
    end
  end

  #
  # Fetches the status of the hwbridge
  #
  def get_status
    data = fetch_json("/status")
    unless data.nil?
      if data.key? 'operational'
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
        if data.key? 'hw_vesrion'
          self.hw_version = data['hw_version']
        end
        if data.key? 'device_name'
          self.device_name = data['device_name']
        end
      end
    end
  end

  def run
    print_status "Attempting to connect to #{datastore['RHOST']}..."
    self.get_status()
    unless @last_access.nil?
      sess = Msf::Sessions::HWBridge.new(self)
      sess.set_from_exploit(self)

      framework.sessions.register(sess)
      print_good "HWBridge session established"
      autoload_extensions(sess)
      load_custom_methods(sess)
      print_status "HW Specialty: #{self.hw_specialty}  Capabilities: #{self.hw_capabilities}"
      print_disclaimer
    else
      print_error "Could not connect to API"
    end
  end

  attr_reader :hw_specialty
  attr_reader :hw_capabilities
  attr_reader :api_version
  attr_reader :fw_version
  attr_reader :hw_version
  attr_reader :device_name

  protected

  attr_writer :hw_specialty
  attr_writer :hw_capabilities
  attr_writer :api_version
  attr_writer :fw_version
  attr_writer :hw_version
  attr_writer :device_name
end
