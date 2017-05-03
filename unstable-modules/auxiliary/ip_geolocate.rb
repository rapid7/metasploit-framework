##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'timeout'
require 'msf/core'
require 'net/http'
require 'rexml/document'
require "net/dns/resolver"

class Metasploit3 < Msf::Auxiliary

	include REXML

	## This module can make use of the local GeoIPCity database and gem for improved
	## querying speeds. It's highly recommended that you follow these instructions
	## and prepare your system for a local DB if you're planning to do more than a few queries

	##  GET THE GEOIP CITY API
	##  wget http://www.maxmind.com/download/geoip/api/c/GeoIP.tar.gz
	##  tar -zxvf GeoIP.tar.gz
	##  cd GeoIP <tab>
	##  ./configure --prefix=/opt/GeoIP
	##  make && sudo make install

	##  GET THE GEOIP_CITY DATABASE
	##  gem install geoip_city -- --with-geoip-dir=/opt/GeoIP

	## GET THE LATEST DATABASE
	## curl -O http://geolite.maxmind.com/download/geoip/database/GeoLiteCity.dat.gz
	## gunzip GeoLiteCity.dat.gz

	## Set the GEOIP_DB variable in metasploit
	## msf (ip_geolocate)> set GEOIP_DB /path/to/GeoLiteCity.dat

	def initialize
		super(
			'Name'        => 'IP Address Geolocation',
			'Description' => %q{
					This module looks up the physical location of an ip address and optionally creates a
					kml file with the mapping. Set the VERBOSE option to see the data. It can be used with
					the IPInfoDB API, or locally with the GeoIP-city database and gem. Instructions have
					been linked in the references section (geoip-howto).
			},
			'References'  => # XXX These references are now invalid, give 404s and other errors.
				[
					[ 'URL', 'http://blog.0x0e.org/2010/11/11/ip-list-to-kml-generator-create-a-google-maep-from-a-list-of-ips/' ],
					[ 'URL', 'http://www.0x0e.org/x/geoip-howto.txt']
				],
			'Author'      => [ 'jcran' ],
			'License'     => MSF_LICENSE
			)

		register_options(
			[
				OptBool.new('USE_LOCAL_DB',		[ true, "Use the Local GeoCityIP API", true]),
				OptPath.new('GEOIP_DB',			[ false, "Local MaxMind GeoCityIP database", 'GeoLiteCity.dat']),
				OptBool.new('GEN_KML',			[ false, "Generate a KML file", true]),
				OptPath.new('KML_FILE',			[ false, "Specify a KML file name", "/tmp/ip_list.kml"]),
				OptString.new('API_KEY', 		[ false, "API Key for IPInfoDB", 'NONE']),
				OptPath.new('IP_FILE', 			[ true, "List of IP Addresses", '/tmp/ip_list']),
				OptBool.new('VERBOSE', 			[ false, "Print the data as it's queried", true]),
				OptBool.new('RESOLVE', 			[ false, "Resolve hostnames", false])
			], self.class)

		register_advanced_options(
			[
				OptAddress.new('NS', 		[ false, "Specify the nameserver to use for queries, otherwise use the system DNS" ]),
				OptInt.new('RETRY', 		[ false, "Number of times to try to resolve a record if no response is received", 2]),
				OptInt.new('RETRY_INTERVAL', 	[ false, "Number of seconds to wait before doing a retry", 2])
			], self.class)
	end

	## The following functions are only for remote querying of info ------
	## Query IPInfoDB for info about the address
	def get_address_remote(ip)
		api_key = datastore['API_KEY']
		url = "http://api.ipinfodb.com/v2/ip_query.php?key=#{api_key}&ip=#{ip}&timezone=false"
		resp = Net::HTTP.get(URI.parse(url))
	end

	## Query Yahoo for info
	def get_coordinates_remote(address)
		#takes a hash with city, state address and returns a hash w/ coords
		url = "http://local.yahooapis.com/MapsService/V1/geocode"
			params = {
				"appid" => "GwLDY.bV34HH7gkBDs97p_5U5P_tBfXBnfDyYFwpTRLwZDEvgj8BOQqws1JOCFPyhTQR",
				"street" => "",
				"city" => address["city"],
				"state" => address["state"]
			}
			resp = Net::HTTP.post_form(URI.parse(url), params)
			resp_text = resp.body
	end

	def parse_address_remote(xml)
		#takes an xml blob with city / state & returns a hash with address,city,state
		doc = Document.new xml
		root = doc.root

		city = root.elements["City"].get_text.to_s
		state = root.elements["RegionName"].get_text.to_s
		country = root.elements["CountryCode"].get_text.to_s

		toReturn = Hash[:city => city, :region => state, :country_name => country]
	end

	def parse_coordinates_remote(xml)
		#takes an xml blob with coordinates & returns a hash with long/lat
		doc = REXML::Document.new xml
		root = doc.root
		long = REXML::XPath.first( doc, "//Longitude" ).get_text.to_s
		lat = REXML::XPath.first( doc, "//Latitude" ).get_text.to_s
		toReturn = Hash[:longitude => long, :latitude => lat]
	end

	## End remote queries -------------------------------


	## Generate an individual placemark for inclusion in the larger KML file
	def gen_placemark(ip,info)
		xml = ""
		xml = xml + "	<Placemark>\n"
		xml = xml + "		<name>" + ip + "</name>\n"
		xml = xml + "		<description>"
		xml = xml + info[:hostname].to_s + ", "
		xml = xml + info[:city].to_s + ", "
		xml = xml + info[:region].to_s + ", "
		xml = xml + info[:country_name].to_s
		xml = xml + "</description>\n"
		xml = xml + "		<Point>\n"
		xml = xml + "			<coordinates>" +
			info[:longitude].to_s  + "," +
			info[:latitude].to_s + ",0</coordinates>\n"
		xml = xml + "		</Point>\n"
		xml = xml + "	</Placemark>\n"
	end

	## Generate the KML skeleton
	def gen_kml(kml_body)
		kml = ""
		kml = kml + "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
		kml = kml + "<kml xmlns=\"http://www.opengis.net/kml/2.2\">\n"
		kml = kml + "<Document>\n"

		kml = kml + kml_body

		kml = kml + "</Document>\n"
		kml = kml + "</kml>\n"
	end

	def mip(ip)

		return if ip == ""
		return unless ::Rex::Socket.dotted_ip?(ip)
		return unless ::Rex::Socket.is_ipv4?(ip)

		ip_info = {	:ip => ip,
				:hostname => "unknown",
				:city => "unknown",
				:region => "unknown",
				:country_name => "unknown"
			}

		loc_info = Hash.new
		if datastore['USE_LOCAL_DB']
			## use the local db
			loc_info = @db.look_up(ip)
		else
			## use the remote API
			xmlAddress = get_address_remote(ip)
			info_address = parse_address_remote(xmlAddress)

			xmlCoordinates = get_coordinates_remote(info_address)
			info_coordinates = parse_coordinates_remote(xmlCoordinates)

			## merge the address & gps info
			loc_info.merge!(info_address)
			loc_info.merge!(info_coordinates)
		end

		if loc_info
			ip_info.merge!(loc_info)
		else
			print_error "#{ip} could not be located in the database"
		end


		if datastore["RESOLVE"]

			answer = nil

			begin
				query = @res.search(ip)
				answer = query.answer.join("/")
			rescue Exception => e
				print_error e.to_s
			end

			if answer
				ip_info[:hostname] = answer
			else
				print_error "#{ip} could not be resolved"
				ip_info[:hostname] = "No PTR."
			end
		else
			## user manually specified this - no need to warn
			ip_info[:hostname] = "Hostname not resolved."
		end

		if datastore['GEN_KML']
			placemark_kml = gen_placemark(ip,ip_info)
			@kml_body = @kml_body + placemark_kml
		end

		if datastore["VERBOSE"]
			print_line "#{ip_info[:ip]} : #{ip_info[:hostname]} : #{ip_info[:city]}, #{ip_info[:region]}, #{ip_info[:country_name]}"
		end
	end

	def mip_file(file)
		counter = 0
		ips = Array.new

		File.open(file, "rb") do |infile|

			while (line = infile.gets)
				ips[counter] = line
				counter = counter + 1
			end
		end

		ips.each do |ip|
			ip = ip.to_s.chomp
			mip(ip)
		end

	end

	def run
		## Check to see if the user wants DNS resolved for each IP, Also check the nameserver
		if datastore['RESOLVE']
			## Set up DNS
			@res = Net::DNS::Resolver.new()
			@res.retry = datastore['RETRY'].to_i
			@res.retry_interval = datastore['RETRY_INTERVAL'].to_i
			@res.tcp_timeout = 10
			@res.udp_timeout = 10

			## Configure the user-specified nameserver
			if datastore['NS']
				print_line("Using DNS Server: #{datastore['NS']}")
				@res.nameserver=(datastore['NS'])
			end
		end

		## Check to see if we should query the data from IPInfoDB / Yahoo, or use a local DB
		if datastore['USE_LOCAL_DB']
			begin
			require 'geoip_city' # see instructions above or in the geoip-howto.txt for how to get this configured
			@db = GeoIPCity::Database.new(datastore['GEOIP_DB'])
			rescue
				print_error "Loading the GeoIPCity database failed. Make sure the database is configured."
				print_error "To configure the database, see the instructions at: http://www.0x0e.org/x/geoip-howto.txt"
				print_error "Remember to configure the module's GEOIP_DB variable as well."
				print_error ""
				print_error "Alternatively, you can  simply set the USE_LOCAL_DB variable to false and a remote API will be queried."
				return
			end

		else
			## Quit if we don't have an API Key...
			if datastore['APIKEY'] == "NONE"
				print_line "You must specify an API key for IPInfoDB.com"
				return
			end
		end

		## start with an empty kml body, in case the user wants to generate it
		@kml_body = ""

		## main function. - read thru the file, map each ip according to the options (also gens the kml body if requested
		mip_file(datastore['IP_FILE'])

		## if the user wants kml, we should have a string ready in the @kml_body var. create it, and write it to a file
		if datastore['GEN_KML']
			kml = gen_kml(@kml_body)
			out = File.new(datastore['KML_FILE'], "wb")
			out.puts kml
			out.close
		end

	end

end
