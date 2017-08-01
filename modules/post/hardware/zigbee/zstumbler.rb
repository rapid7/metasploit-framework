##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/post/hardware/zigbee/utils'

class MetasploitModule < Msf::Post
  include Msf::Post::Hardware::Zigbee::Utils

  def initialize(info={})
    super( update_info( info,
        'Name'          => 'Sends Beacons to Scan for Active ZigBee Networks',
        'Description'   => %q{ Post Module to send beacon signals to the broadcast address while
                               channel hopping},
        'License'       => MSF_LICENSE,
        'Author'        => ['Craig Smith'],
        'Platform'      => ['hardware'],
        'SessionTypes'  => ['hwbridge']
      ))
    register_options([
      OptInt.new('CHANNEL', [false, "Disable channel hopping by forcing a channel (11-26)", nil]),
      OptInt.new('LOOP', [false, "How many times to loop over the channels (-1 will run in an endless loop)", 1]),
      OptInt.new('DELAY', [false, "Delay in seconds to listen on each channel", 2]),
      OptString.new('DEVICE', [false, "ZigBee device ID, defaults to target device", nil])
    ])
    @seq = 0
    @channel = 11
    @stumbled = {}
    @loop_count = 0
  end

  def display_details(routerdata)
    stackprofile_map = {0 => "Network Specific",
                        1 => "ZigBee Standard",
                        2 => "ZigBee Enterprise"}
    stackver_map = {0 => "ZigBee Prototype",
                    1 => "ZigBee 2004",
                    2 => "ZigBee 2006/2007"}
    spanid, source, extpanid, stackprofilever, channel = routerdata
    stackprofilever =  stackprofilever.unpack("H*")[0].hex
    stackprofile = stackprofilever & 0x0f
    stackver = (stackprofilever & 0xf0) >> 4
    profile = "Unknown"
    profile = stackprofile_map[stackprofile] if stackprofile_map.has_key? stackprofile
    ver = "Unknown"
    ver = stackver_map[stackver] if stackver_map.has_key? stackver
    print_status("New Network: PANID: 0x#{spanid.upcase} SOURCE: 0x#{source.upcase}")
    print_status("        Ext PANID: #{extpanid.upcase.scan(/../).join(':')}       Stack Profile: #{profile}")
    print_status("        Stack Version: #{ver}")
    print_status("        Channel: #{@channel}")
  end

  def scan
    @seq = 0 if @seq > 255
    print_status("Scanning Channel #{@channel}")
    set_channel(datastore["DEVICE"], @channel)
    beacon = "\x03\x08#{@seq.chr}\xff\xff\xff\xff\x07"
    inject(datastore["DEVICE"], beacon)
    delay = Time.now + datastore["DELAY"]
    while delay > Time.now()
      pkt = recv(datastore["DEVICE"])
      if pkt and pkt.size > 0 and pkt["valid_crc"]
        pktdecode = dot154_packet_decode(pkt["data"])
        if (pktdecode["FSF"] & DOT154_FCF_TYPE_MASK) == DOT154_FCF_TYPE_BEACON
          key = "#{pktdecode["SPAN_ID"]}#{pktdecode["SOURCE"]}"
          value = [pktdecode["SPAN_ID"], pktdecode["SOURCE"], pktdecode["EXT_PAN_ID"], pktdecode["STACK_PROFILE"], @channel]
          if not @stumbled.has_key? key
              @stumbled[key] = value
              display_details(value)
          end
        end
      end
    end
    sniffer_off(datastore["DEVICE"]) # Needed to clear receive buffers
    @seq += 1
    @channel += 1 if not datastore["CHANNEL"]
    @loop_count += 1 if @channel > 26 or datastore["CHANNEL"]
    @channel = 11 if @channel > 26
  end

  def run
    if not get_target_device and not datastore["DEVICE"]
      print_error "No target device set.  Either set one with the 'target' command or specify the DEVICE."
      return
    end
    @channel = datastore["CHANNEL"] if datastore["CHANNEL"]
    @channel = 11 if @channel > 26
    if datastore["LOOP"] == -1
      while(1) do
        scan
      end
    else
      while(@loop_count < datastore["LOOP"])
        scan
      end
    end
  end
end
