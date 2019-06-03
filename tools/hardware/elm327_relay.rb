#!/usr/bin/env ruby

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

#
# ELM327 and STN1100 MCU interface to the Metasploit HWBridge
#

#
# This module requires a connected ELM327 or STN1100 is connected to
# the machines serial. Sets up a basic RESTful web server to communicate
#
# Requires MSF and the serialport gem to be installed.
# - `gem install serialport`
# - or, if using rvm: `rvm gemset install serialport`
#

### Non-typical gem ###
begin
  require 'serialport'
rescue LoadError => e
  gem = e.message.split.last
  abort "#{gem} gem is not installed. Please install with `gem install #{gem}' or, if using rvm, `rvm gemset install #{gem}' and try again."
end

#
# Load our MSF API
#

msfbase = __FILE__
while File.symlink?(msfbase)
  msfbase = File.expand_path(File.readlink(msfbase), File.dirname(msfbase))
end
$:.unshift(File.expand_path(File.join(File.dirname(msfbase), '..', '..', 'lib')))
require 'msfenv'
require 'rex'
require 'msf/core'
require 'optparse'

# Prints with [*] that represents the message is a status
#
# @param msg [String] The message to print
# @return [void]
def print_status(msg='')
  $stdout.puts "[*] #{msg}"
end

# Prints with [-] that represents the message is an error
#
# @param msg [String] The message to print
# @return [void]
def print_error(msg='')
  $stdout.puts "[-] #{msg}"
end

# Base ELM327 Class for the Realy
module ELM327HWBridgeRelay

  class ELM327Relay < Msf::Auxiliary

    include Msf::Exploit::Remote::HttpServer::HTML

    # @!attribute serial_port
    #  @return [String] The serial port device name
    attr_accessor :serial_port

    # @!attribute serial_baud
    #  @return [Integer] Baud rate of serial device
    attr_accessor :serial_baud

    # @!attribute serial_bits
    #  @return [Integer] Number of serial data bits
    attr_accessor :serial_bits

    # @!attribute serial_stop_bits
    #  @return [Integer] Stop bit
    attr_accessor :serial_stop_bits

    # @!attribute server_port
    #  @return [Integer] HTTP Relay server port
    attr_accessor :server_port

    def initialize(info={})
      # Set some defaults
      self.serial_port = "/dev/ttyUSB0"
      self.serial_baud = 115200
      begin
        @opts = OptsConsole.parse(ARGV)
      rescue OptionParser::InvalidOption, OptionParser::MissingArgument => e
        print_error("#{e.message} (please see -h)")
        exit
      end

      if @opts.has_key? :server_port
        self.server_port = @opts[:server_port]
      else
        self.server_port = 8080
      end

    super(update_info(info,
      'Name'        => 'ELM327/STN1100 HWBridge Relay Server',
      'Description' => %q{
          This module sets up a web server to bridge communications between
        Metasploit and the EML327 or STN1100 chipset.
      },
      'Author'      => [ 'Craig Smith' ],
      'License'     => MSF_LICENSE,
      'Actions'     =>
        [
          [ 'WebServer' ]
        ],
      'PassiveActions' =>
        [
          'WebServer'
        ],
      'DefaultAction'  => 'WebServer',
        'DefaultOptions' =>
         {
            'SRVPORT' => self.server_port,
            'URIPATH' => "/"
          }))
       self.serial_port = @opts[:serial] if @opts.has_key? :serial
       self.serial_baud = @opts[:baud].to_i if @opts.has_key? :baud
       self.serial_bits = 8
       self.serial_stop_bits = 1
       @operational_status = 0
       @ser = nil # Serial Interface
       @device_name = ""
       @packets_sent = 0
       @last_sent = 0
       @starttime = Time.now()
       @supported_buses = [ { "bus_name" => "can0" } ]
    end

    # Sends a serial command to the ELM327. Automatically appends \r\n
    #
    # @param cmd [String] Serial AT command for ELM327
    # @return [String] Response between command and '>' prompt
    def send_cmd(cmd)
      @ser.write(cmd + "\r\n")
      resp = @ser.readline(">")
      resp = resp[0, resp.length - 2]
      resp.chomp!
      resp
    end

    # Connects to the ELM327, resets paramters, gets device version and sets up general comms.
    # Serial params are set via command options or during initialization
    #
    # @return [SerialPort] SerialPort object for communications. Also available as @ser
    def connect_to_device()
      begin
        @ser = SerialPort.new(self.serial_port, self.serial_baud, self.serial_bits, self.serial_stop_bits, SerialPort::NONE)
      rescue
        $stdout.puts "Unable to connect to serial port.  See -h for help"
        exit -2
      end
      resp = send_cmd("ATZ")  # Turn off ECHO
      if resp =~ /ELM327/
        send_cmd("ATE0")  # Turn off ECHO
        send_cmd("ATL0")  # Disble linefeeds
        @device_name = send_cmd("ATI")
        send_cmd("ATH1") # Show Headers
        @operational_status = 1
        $stdout.puts("Connected.  Relay is up and running...")
      else
        $stdout.puts("Connected but invalid ELM response: #{resp.inspect}")
        @operational_status = 2
        # Down the road we may make a way to re-init via the hwbridge but for now just exit
        $stdout.puts("The device may not have been fully initialized, try reconnecting")
        exit(-1)
      end
      @ser
    end

    # HWBridge Status call
    #
    # @return [Hash] Status return hash
    def get_status()
      status = Hash.new
      status["operational"] = @operational_status
      status["hw_specialty"] = { "automotive" => true }
      status["hw_capabilities"] = { "can" => true}
      status["last_10_errors"] = @last_errors # NOTE: no support for this yet
      status["api_version"] = "0.0.1"
      status["fw_version"] = "not supported"
      status["hw_version"] = "not supported"
      status["device_name"] = @device_name
      status
    end

    # HWBridge Statistics Call
    #
    # @return [Hash] Statistics return hash
    def get_statistics()
      stats = Hash.new
      stats["uptime"] = Time.now - @starttime
      stats["packet_stats"] = @packets_sent
      stats["last_request"] = @last_sent
      volt = send_cmd("ATRV")
      stats["voltage"] = volt.gsub(/V/,'')
      stats
    end

    # HWBRidge DateTime Call
    #
    # @return [Hash] System DateTime Hash
    def get_datetime()
      { "sytem_datetime" => Time.now() }
    end

    # HWBridge Timezone Call
    #
    # @return [Hash] System Timezone as String
    def get_timezone()
      { "system_timezone" => Time.now.getlocal.zone }
    end

    # Returns supported buses. Can0 is always available
    # TODO: Use custom methods to force non-standard buses such as kline
    #
    # @return [Hash] Hash of supported_buses
    def get_supported_buses()
      @supported_buses
    end

    # Sends CAN packet
    #
    # @param id [String] ID as a hex string
    # @param data [String] String of HEX bytes to send
    # @return [Hash] Success Hash
    def cansend(id, data)
      result = {}
      result["success"] = false
      id = "%03X" % id.to_i(16)
      resp = send_cmd("ATSH#{id}")
      if resp == "OK"
        send_cmd("ATR0") # Disable response checks
        send_cmd("ATCAF0") # Turn off ISO-TP formatting
      else
        return result
      end
      if data.scan(/../).size > 8
        $stdout.puts("Error: Data size > 8 bytes")
        return result
      end
      send_cmd(data)
      @packets_sent += 1
      @last_sent = Time.now()
      if resp == "CAN ERROR"
        result["success"] = false
        return result
      end
      result["success"] = true
      result
    end

    # Sends ISO-TP Packets
    #
    # @param srcid [String] Sender ID as hex string
    # @param dstid [String] Responder ID as hex string
    # @param data [String] Hex String of data to send
    # @param timeout [Integer] Millisecond timeout, currently not implemented
    # @param maxpkts [Integer] Max number of packets in response, currently not implemented
    def isotpsend_and_wait(srcid, dstid, data, timeout, maxpkts)
      result = {}
      result["success"] = false
      srcid = "%03X" % srcid.to_i(16)
      dstid = "%03X" % dstid.to_i(16)
      send_cmd("ATCAF1")         # Turn on ISO-TP formatting
      send_cmd("ATR1")           # Turn on responses
      send_cmd("ATSH#{srcid}")   # Src Header
      send_cmd("ATCRA#{dstid}")  # Resp Header
      send_cmd("ATCFC1").        # Enable flow control
      resp = send_cmd(data)
      @packets_sent += 1
      @last_sent = Time.now()
      if resp == "CAN ERROR"
        result["success"] = false
        return result
      end
      result["Packets"] = []
      resp.split(/\r/).each do |line|
        pkt = {}
        if line=~/^(\w+) (.+)/
          pkt["ID"] = $1
          pkt["DATA"] = $2.split
        end
        result["Packets"] << pkt
      end
      result["success"] = true
      result
    end

    # Generic Not supported call
    #
    # @return [Hash] Status not supported
    def not_supported()
      { "status" => "not supported" }
    end

    # Handles incomming URI requests and calls their respective API functions
    #
    # @param cli [Socket] Socket for the browser
    # @param request [Rex::Proto::Http::Request] HTTP Request sent by the browser
    def on_request_uri(cli, request)
      if request.uri =~ /status$/i
        send_response_html(cli, get_status().to_json(), { 'Content-Type' => 'application/json' })
      elsif request.uri =~ /statistics$/i
        send_response_html(cli, get_stats().to_json(), { 'Content-Type' => 'applicaiton/json' })
      elsif request.uri =~/settings\/datetime$/i
        send_response_html(cli, get_datetime().to_json(), { 'Content-Type' => 'application/json' })
      elsif request.uri =~/settings\/timezone$/i
        send_response_html(cli, get_timezone().to_json(), { 'Content-Type' => 'application/json' })
#      elsif request.uri =~/custom_methods$/i
#        send_response_html(cli, get_custom_methods().to_json(), { 'Content-Type' => 'application/json' })
      elsif request.uri =~/automotive/i
        if request.uri =~/automotive\/supported_buses/i
          send_response_html(cli, get_supported_buses().to_json(), { 'Content-Type' => 'application/json' })
        elsif request.uri =~/automotive\/can0\/cansend/
          params = CGI.parse(URI(request.uri).query)
          if params.has_key? "id" and params.has_key? "data"
            send_response_html(cli, cansend(params["id"][0], params["data"][0]).to_json(), { 'Content-Type' => 'application/json' })
          else
            send_response_html(cli, not_supported().to_json(), { 'Content-Type' => 'application/json' })
          end
        elsif request.uri =~/automotive\/can0\/isotpsend_and_wait/
          params = CGI.parse(URI(request.uri).query)
          if params.has_key? "srcid" and params.has_key? "dstid" and params.has_key? "data"
            timeout = 1500
            maxpkts = 3
            timeout = params["timeout"][0] if params.has_key? "timeout"
            maxpkts = params["maxpkts"][0] if params.has_key? "maxpkts"
            send_response_html(cli, isotpsend_and_wait(params["srcid"][0], params["dstid"][0], params["data"][0], timeout, maxpkts).to_json(), { 'Content-Type' => 'application/json' })
          else
            send_response_html(cli, not_supported().to_json(), { 'Content-Type' => 'application/json' })
          end
        else
          send_response_html(cli, not_supported().to_json(), { 'Content-Type' => 'application/json' })
        end
      else
        send_response_html(cli, not_supported().to_json(), { 'Content-Type' => 'application/json' })
      end
    end

    # Main run operation. Connects to device then runs the server
    def run
      connect_to_device()
      exploit()
    end

  end

  # This class parses the user-supplied options (inputs)
  class OptsConsole

    DEFAULT_BAUD = 115200
    DEFAULT_SERIAL = "/dev/ttyUSB0"

    # Returns the normalized user inputs
    #
    # @param args [Array] This should be Ruby's ARGV
    # @raise [OptionParser::MissingArgument] Missing arguments
    # @return [Hash] The normalized options
    def self.parse(args)
      parser, options = get_parsed_options

      # Now let's parse it
      # This may raise OptionParser::InvalidOption
      parser.parse!(args)

      options
    end

    # Returns the parsed options from ARGV
    #
    # raise [OptionParser::InvalidOption] Invalid option found
    # @return [OptionParser, Hash] The OptionParser object and an hash containing the options
    def self.get_parsed_options
      options = {}
      parser = OptionParser.new do |opt|
        opt.banner = "Usage: #{__FILE__} [options]"
        opt.separator ''
        opt.separator 'Specific options:'

        opt.on('-b', '--baud <serial_baud>',
          "(Optional) Sets the baud speed for the serial device (Default=#{DEFAULT_BAUD})") do |v|
          options[:baud] = v
        end

        opt.on('-s', '--serial <serial_device>',
          "(Optional) Sets the serial device (Default=#{DEFAULT_SERIAL})") do |v|
          options[:serial] = v
        end

        opt.on('-p', '--port <server_port>',
          "(Optional) Sets the listening HTTP server port (Default=8080)") do |v|
          options[:server_port] = v
        end

        opt.on_tail('-h', '--help', 'Show this message') do
          $stdout.puts opt
          exit
        end
      end
      return parser, options
    end
  end
end



#
# Main
#
if __FILE__ == $PROGRAM_NAME
  begin
    bridge = ELM327HWBridgeRelay::ELM327Relay.new
    bridge.run
  rescue Interrupt
    $stdout.puts("Shutting down")
  end
end

