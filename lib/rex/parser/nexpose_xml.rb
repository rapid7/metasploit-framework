module Rex
module Parser

# XXX doesn't tie services to vulns
class NexposeXMLStreamParser

	attr_accessor :callback

	def initialize(callback = nil)
		reset_state
		self.callback = callback if callback
	end

	def reset_state
		@state = :generic_state
		@host = { "status" => nil, "endpoints" => [], "names" => [], "vulns" => {} }
		@vuln = { "refs" => [] }
	end

	def tag_start(name, attributes)
		case name
		when "node"
			@host["hardware-address"] = attributes["hardware-address"]
			@host["addr"] = attributes["address"]
			@host["status"] = attributes["status"]
		when "os"
			# Take only the highest certainty
			if not @host["os_certainty"] or (@host["os_certainty"].to_f < attributes["certainty"].to_f)
				@host["os_vendor"]    = attributes["vendor"]
				@host["os_family"]    = attributes["family"]
				@host["os_product"]   = attributes["product"]
				@host["arch"]         = attributes["arch"]
				@host["os_certainty"] = attributes["certainty"]
			end
		when "name"
			#@host["names"].push attributes["name"]
			@state = :in_name
		when "endpoint"
			# This is a port in NeXpose parlance
			@host["endpoints"].push(attributes)
		when "service"
			@state = :in_service
			# Store any service info with the associated port.  There shouldn't
			# be any collisions on attribute names here, so just merge them.
			@host["endpoints"].last.merge!(attributes)
		when "fingerprint"
			if @state == :in_service
				@host["endpoints"].last.merge!(attributes)
			end
		when "test"
			if attributes["status"] == "vulnerable-exploited" or attributes["status"] == "vulnerable-version"
				@host["vulns"][attributes["id"]] = attributes.dup
			end
		when "vulnerability"
			@vuln.merge! attributes
		when "reference"
			@state = :in_reference
			@vuln["refs"].push attributes
		end
	end

	def text(str)
		case @state
		when :in_name
			@host["names"].push str
		when :in_reference
			@vuln["refs"].last["value"] = str
		end
	end

	def tag_end(name)
		case name
		when "node"
			callback.call(:host, @host) if callback
			reset_state
		when "vulnerability"
			callback.call(:vuln, @vuln) if callback
			reset_state
		when "service","reference"
			@state = :generic_state
		end
	end

	# We don't need these methods, but they're necessary to keep REXML happy
	def xmldecl(version, encoding, standalone); end
	def cdata; end
	def comment(str); end
	def instruction(name, instruction); end
	def attlist; end
end
end
end

__END__

<node address="10.1.1.10" status="alive" hardware-address="0007371F3BE8">
<names>
<name>NETBIOSNAME</name>
<name>hostname.example.com</name>
</names>
<fingerprints>
<os  certainty="1.00" device-class="Domain controller" vendor="Microsoft" family="Windows" product="Windows Server 2003, Standard Edition" version="SP2" arch="x86"/>
<os  certainty="0.85" device-class="General" vendor="Microsoft" family="Windows" product="Windows Server 2003"/>
<os  certainty="0.70" vendor="Microsoft" family="Windows" product="Windows Server 2003"/>
</fingerprints>
<software>
<fingerprint  certainty="1.00" vendor="Acronis" product="Acronis&#160;True&#160;Image&#160;Echo&#160;Server" version="9.5.8163"/>
<fingerprint  certainty="1.00" vendor="Acronis" product="Acronis&#160;Universal&#160;Restore for Acronis&#160;True&#160;Image&#160;Echo&#160;Server" version="9.5.8076"/>
<fingerprint  certainty="1.00" software-class="Internet Client" vendor="Microsoft" family="Internet Explorer" product="Internet Explorer" version="7.0.5730.11"/>
<fingerprint  certainty="1.00" software-class="Database Client" vendor="Microsoft" family="MDAC" product="MDAC" version="2.8"/>
<fingerprint  certainty="1.00" software-class="Media Client" vendor="Microsoft" family="Windows Media Player" product="Windows Media Player" version="10.0.0.3997"/>
<fingerprint  certainty="1.00" vendor="MySolutions NORDIC" product="NSClient++ (Win32)" version="0.3.4.0"/>
<fingerprint  certainty="1.00" vendor="Symantec Corporation" product="LiveUpdate 3.1 (Symantec Corporation)" version="3.1.0.99"/>
<fingerprint  certainty="1.00" vendor="Symantec Corporation" product="Symantec AntiVirus" version="10.1.5000.5"/>
</software>
<tests>
<test status="not-vulnerable" id="backdoor-ckb.cfaae1e6">

<endpoint protocol="tcp" port="139" status="open">
<services>
<service name="CIFS">
<fingerprints>
<fingerprint  certainty="1.00" product="Windows Server 2003 R2 5.2"/>
</fingerprints>
<tests>
</tests>
</service>
</services>
</endpoint>
</node>

