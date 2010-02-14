
require 'rexml/document'

module Rex
module Parser

#
# Stream parser for nmap -oX xml output
#
# Yields a hash representing each host found in the xml stream.  Each host
# will look something like the following:
#	{
#		"status" => "up",
#		"addrs"  => { "ipv4" => "192.168.0.1", "mac" => "00:0d:87:a1:df:72" },
#		"ports"  => [
#			{ "portid" => "22", "state" => "closed", ... },
#			{ "portid" => "80", "state" => "open", ... },
#			...
#		]
#	}
#
# Usage:
# <tt>
# parser = NmapXMLStreamParser.new { |host|
#	# do stuff with the host
# }
# REXML::Document.parse_stream(File.new(nmap_xml), parser)
# </tt>
# -- or --
# <tt>
# parser = NmapXMLStreamParser.new
# parser.on_found_host = Proc.new { |host|
#	# do stuff with the host
# }
# REXML::Document.parse_stream(File.new(nmap_xml), parser)
# </tt>
#
# This parser does not maintain state as well as a tree parser, so malformed
# xml will trip it up.  Nmap shouldn't ever output malformed xml, so it's not
# a big deal.
#
class NmapXMLStreamParser

	attr_accessor :on_found_host

	def initialize(&block)
		reset_state
		on_found_host = block if block
	end

	def reset_state
		@host = { "status" => nil, "addrs" => {}, "ports" => [] }
	end

	def tag_start(name, attributes)
		case name
		when "address"
			@host["addrs"][attributes["addrtype"]] = attributes["addr"]
			if (attributes["addrtype"] =~ /ipv[46]/)
				@host["addr"] = attributes["addr"]
			end
		when "osclass"
			@host["os_vendor"]   = attributes["vendor"]
			@host["os_family"]   = attributes["osfamily"]
			@host["os_version"]  = attributes["osgen"]
			@host["os_accuracy"] = attributes["accuracy"]
		when "uptime"
			@host["last_boot"]   = attributes["lastboot"]
		when "hostname"
			if(attributes["type"] == "PTR")
				@host["reverse_dns"] = attributes["name"]
			end
		when "status"
			# <status> refers to the liveness of the host; values are "up" or "down"
			@host["status"] = attributes["state"]
		when "port"
			@host["ports"].push(attributes)
		when "state"
			# <state> refers to the state of a port; values are "open", "closed", or "filtered"
			@host["ports"].last["state"] = attributes["state"]
		when "service"
			# Store any service info with the associated port.  There shouldn't
			# be any collisions on attribute names here, so just merge them.
			@host["ports"].last.merge!(attributes)
		end
	end

	def tag_end(name)
		case name
		when "host"
			on_found_host.call(@host) if on_found_host
			reset_state
		end
	end

	# We don't need these methods, but they're necessary to keep REXML happy
	def text(str); end
	def xmldecl(version, encoding, standalone); end
	def cdata; end
	def comment(str); end
	def instruction(name, instruction); end
	def attlist; end
end

end
end

