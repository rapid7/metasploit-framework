##
#
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
#
# TODO: SSL Support, Authentication, Listen to localhost only by default
#
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpServer::HTML
  include Msf::Auxiliary::Report

  HWBRIDGE_API_VERSION = "0.0.4"

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'Hardware Bridge Server',
      'Description' => %q{
          This module sets up a web server to bridge communications between
        Metasploit and physically attached hardware.
        Currently this module supports: automotive
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
      'DefaultAction'  => 'WebServer'))

    @operational_status = 0   # 0=unk, 1=connected, 2=not connected
    @last_errors = {}
    @server_started = Time.new
    @can_interfaces = []
    @pkt_response = {}  # Candump returned packets
    @packets_sent = 0
    @last_sent = nil
  end

  def detect_can
    @can_interfaces = []
    Socket.getifaddrs.each do |i|
      if i.name =~ /^can\d+$/ || i.name =~ /^vcan\d+$/ || i.name =~ /^slcan\d+$/
        @can_interfaces << i.name
      end
    end
  end

  def get_status
    status = {}
    status["operational"] = @operational_status
    status["hw_specialty"] = {}
    status["hw_capabilities"] = {}
    status["last_10_errors"] = @last_errors # NOTE: no support for this yet
    status["api_version"] = HWBRIDGE_API_VERSION
    status["fw_version"] = "not supported"
    status["hw_version"] = "not supported"
    unless @can_interfaces.empty?
      status["hw_specialty"]["automotive"] = true
      status["hw_capabilities"]["can"] = true
    end
    status["hw_capabilities"]["custom_methods"] = true # To test custom methods
    status
  end

  def get_statistics
    stats = {}
    stats["uptime"] = Time.now - @server_started
    stats["packet_stats"] = @packets_sent
    stats["last_request"] = @last_sent if @last_sent
    stats["voltage"] = "not supported"
    stats
  end

  def get_datetime
    { "system_datetime" => Time.now }
  end

  def get_timezone
    { "system_timezone" => Time.now.getlocal.zone }
  end

  def get_ip_config
  end

  #
  # Stub fucntion to test custom methods
  # Defines a method "sample_cmd" with one argument "data" which is required
  #
  def get_custom_methods
    m = {}
    m["Methods"] = []
    meth = { "method_name" => "custom/sample_cmd", "method_desc" => "Sample HW test command", "args" => [] }
    arg = { "arg_name" => "data", "arg_type" => "string", "required" => true }
    meth["args"] << arg
    meth["return"] = "string"
    m["Methods"] << meth
    m
  end

  def get_auto_supported_buses
    detect_can()
    buses = []
    @can_interfaces.each do |can|
      buses << { "bus_name" => can }
    end
    buses
  end

  # Sends a raw CAN packet
  # bus = string
  # id = hex ID
  # data = string of up to 8 hex bytes
  def cansend(bus, id, data)
    result = {}
    result["Success"] = false
    id = id.to_i(16).to_s(16)  # Clean up the HEX
    bytes = data.scan(/../)  # Break up data string into 2 char (byte) chunks
    if bytes.size > 8
      print_error("Data section can only contain a max of 8 bytes")
      return result
    end
    `which cansend`
    unless $?.success?
      print_error("cansend from can-utils not found in path")
      return result
    end
    @can_interfaces.each do |can|
      if can == bus
        system("cansend #{bus} #{id}##{bytes.join}")
        @packets_sent += 1
        @last_sent = Time.now.to_i
        result["Success"] = true if $?.success?
      end
    end
    result
  end

  # Converts candump output to {Packets => [{ ID=> id DATA => [] }]}
  def candump2hash(str_packets)
    hash = {}
    hash["Packets"] = []
    lines = str_packets.split(/\n/)
    lines.each do |line|
      if line =~ /\w+\s+(\w+)   \[\d\]  (.+)$/
        id = $1
        str_data = $2
        data = str_data.split
        hash["Packets"] << { "ID" => id, "DATA" => data }
      end
    end
    hash
  end

  def candump(bus, id, timeout, maxpkts)
    $candump_sniffer = Thread.new do
      output = `candump #{bus},#{id}:FFFFFF -T #{timeout} -n #{maxpkts}`
      @pkt_response = candump2hash(output)
      Thread::exit
    end
  end

  # Sends an ISO-TP style CAN packet and waites for a response or a timeout
  # bus = string
  # srcid = hex id of the sent packet
  # dstid = hex id of the return packets
  # data = string of hex bytes to send
  # OPT = Options
  #    timeout = optional int to timeout on lack of response
  #    maxpkts = max number of packets to recieve
  #    padding = append bytes to end of packet (Doesn't increase reported ISO-TP size)
  #    fc = flow control, if true forces flow control packets
  def isotp_send_and_wait(bus, srcid, dstid, data, opt = {})
    result = {}
    result["Success"] = false
    srcid = srcid.to_i(16).to_s(16)
    dstid = dstid.to_i(16).to_s(16)
    timeout = 2000
    maxpkts = 3
    flowcontrol = nil
    padding = nil
    timeout = opt['TIMEOUT'] if opt.key? 'TIMEOUT'
    maxpkts = opt['MAXPKTS'] if opt.key? 'MAXPKTS'
    padding = opt['PADDING'] if opt.key? 'PADDING'
    flowcontrol = opt['FC'] if opt.key? 'FC'
    bytes = data.scan(/../)
    if bytes.size > 8
      print_error("Data section currently has to be less than 8 bytes")
      return result
    else
      sz = "%02x" % bytes.size
      bytes = sz + bytes.join
    end
    if padding && bytes.size < 16 # 16 == 8 bytes because of ascii size
      padding = "%02x" % padding.to_i
      bytes += ([ padding ] * (16 - bytes.size)).join
    end
    # Should we ever require isotpsend for this?
    `which cansend`
    unless $?.success?
      print_error("cansend from can-utils not found in path")
      return result
    end
    @can_interfaces.each do |can|
      if can == bus
        if flowcontrol
          candump(bus, dstid, timeout, 1)
          system("cansend #{bus} #{srcid}##{bytes}")
          @packets_sent += 1
          @last_sent = Time.now.to_i
          result["Success"] = true if $?.success?
          result["Packets"] = []
          $candump_sniffer.join
          unless @pkt_response.empty?
            result = @pkt_response
            if result.key?("Packets") && result["Packets"].size > 0 && result["Packets"][0].key?("DATA")
              if result["Packets"][0]["DATA"][0] == "10"
                system("cansend #{bus} #{srcid}#3000000000000000")
                candump(bus, dstid, timeout, maxpkts)
                @packets_sent += 1
                @last_sent = Time.now.to_i
                $candump_sniffer.join
                unless @pkt_response.empty?
                  if @pkt_response.key?("Packets") && @pkt_response["Packets"].size > 0
                    result["Packets"] += @pkt_response["Packets"]
                  end
                end
              end
            end
          end

        else
          candump(bus, dstid, timeout, maxpkts)
          system("cansend #{bus} #{srcid}##{bytes}")
          @packets_sent += 1
          @last_sent = Time.now.to_i
          result["Success"] = true if $?.success?
          result["Packets"] = []
          $candump_sniffer.join
          unless @pkt_response.empty?
            result = @pkt_response
          end
        end
      end
    end
    result

  end

  #
  # This is just a sample method that should show up
  # as sample_cmd in the interface
  #
  def sample_custom_method(data)
    res = {}
    res["value"] = "Succesfully processed: #{data}"
    res
  end

  def not_supported
    { "status" => "not supported" }
  end

  def on_request_uri(cli, request)
    if request.uri =~ /status$/i
      print_status("Sending status...") if datastore['VERBOSE']
      send_response_html(cli, get_status().to_json(), { 'Content-Type' => 'application/json' })
    elsif request.uri =~ /statistics$/i
      print_status("Sending statistics...") if datastore['VERBOSE']
      send_response_html(cli, get_statistics().to_json(), { 'Content-Type' => 'application/json' })
    elsif request.uri =~ /settings\/datetime\/get$/i
      print_status("Sending Datetime") if datastore['VERBOSE']
      send_response_html(cli, get_datetime().to_json(), { 'Content-Type' => 'application/json' })
    elsif request.uri =~ /settings\/timezone\/get$/i
      print_status("Sending Timezone") if datastore['VERBOSE']
      send_response_html(cli, get_timezone().to_json(), { 'Content-Type' => 'application/json' })
    elsif request.uri =~ /custom_methods$/i
      print_status("Sending custom methods") if datastore['VERBOSE']
      send_response_html(cli, get_custom_methods().to_json(), { 'Content-Type' => 'application/json' })
    elsif request.uri =~ /custom\/sample_cmd\?data=(\S+)$/
      print_status("Request for custom command with args #{$1}") if datastore['VERBOSE']
      send_response_html(cli, sample_custom_method($1).to_json(), { 'Content-Type' => 'application/json' })
    elsif request.uri =~ /automotive/i
      if request.uri =~ /automotive\/supported_buses/
        print_status("Sending known buses...") if datastore['VERBOSE']
        send_response_html(cli, get_auto_supported_buses().to_json, { 'Content-Type' => 'application/json' })
      elsif request.uri =~ /automotive\/(\w+)\/cansend\?id=(\w+)&data=(\w+)/
        print_status("Request to send CAN packets for #{$1} => #{$2}##{$3}") if datastore['VERBOSE']
        send_response_html(cli, cansend($1, $2, $3).to_json(), { 'Content-Type' => 'application/json' })
      elsif request.uri =~ /automotive\/(\w+)\/isotpsend_and_wait\?srcid=(\w+)&dstid=(\w+)&data=(\w+)/
        bus = $1; srcid = $2; dstid = $3; data = $4
        print_status("Request to send ISO-TP packet and wait for response  #{srcid}##{data} => #{dstid}") if datastore['VERBOSE']
        opt = {}
        opt['TIMEOUT'] = $1 if request.uri =~ /&timeout=(\d+)/
        opt['MAXPKTS'] = $1 if request.uri =~ /&maxpkts=(\d+)/
        opt['PADDING'] = $1 if request.uri =~ /&padding=(\d+)/
        opt['FC'] = true if request.uri =~ /&fc=true/i
        send_response_html(cli, isotp_send_and_wait(bus, srcid, dstid, data, opt).to_json(),  { 'Content-Type' => 'application/json' })
      else
        send_response_html(cli, not_supported().to_json(), { 'Content-Type' => 'application/json' })
      end
    else
      send_response_html(cli, not_supported().to_json(), { 'Content-Type' => 'application/json' })
    end
  end

  def run
    detect_can
    @server_started = Time.now
    exploit
  end
end
