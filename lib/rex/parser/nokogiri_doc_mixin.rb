module Rex
	module Parser

		# Determines if Nokogiri is available and if it's a minimum
		# acceptable version.
		def self.load_nokogiri
			@nokogiri_loaded = false
			begin
				require 'nokogiri'
				major,minor = Nokogiri::VERSION.split(".")[0,2]
				if major.to_i >= 1
					if minor.to_i >= 4
						@nokogiri_loaded = true
					end
				end
			rescue LoadError => e
				@nokogiri_loaded = false
				@nokogiri_error  = e
			end
			@nokogiri_loaded
		end

		def self.nokogiri_loaded
			!!@nokogiri_loaded
		end

	end
end

module Rex
module Parser

		load_nokogiri && module NokogiriDocMixin

		# Set up the getters and instance variables for the document
		eval("attr_reader :args, :db, :state, :block, :report_data")

		def initialize(args,db,&block)
			@args = args
			@db = db
			@state = {}
			@state[:current_tag] = {}
			@block = block if block
			@report_data = {:wspace => args[:wspace]}
			super()
		end

		# Turn XML attribute pairs in to more workable hashes (there
		# are better Enumerable tricks in Ruby 1.9, but ignoring for now)
		def attr_hash(attrs)
			h = {}
			attrs.each {|k,v| h[k] = v}
			h
		end

		def valid_ip(addr)
			valid = false
			valid = ::Rex::Socket::RangeWalker.new(addr).valid? rescue false
			!!valid
		end

		# If there's an address, it's not on the blacklist, 
		# it has ports, and the port list isn't
		# empty... it's okay.
		def host_is_okay
			return false unless @report_data[:host]
			return false unless valid_ip(@report_data[:host])
			return false unless @report_data[:state] == Msf::HostState::Alive
			if @args[:blacklist]
				return false if @args[:blacklist].include?(@report_data[:host])
			end
			return false unless @report_data[:ports]
			return false if @report_data[:ports].empty?
			return true
		end

		# XXX: Define this
		def determine_port_state(v)
			return v
		end

		# Nokogiri 1.4.4 (and presumably beyond) generates attrs as pairs,
		# like [["value1","foo"],["value2","bar"]] (but not hashes for some 
		# reason). 1.4.3.1 (and presumably 1.4.3.x and prior) generates attrs
		# as a flat array of strings. We want array_pairs.
		def normalize_attrs(attrs)
			attr_pairs = []
			case attrs.first
			when Array, NilClass
				attr_pairs = attrs
			when String
				attrs.each_index {|i| 
					next if i % 2 == 0
					attr_pairs << [attrs[i-1],attrs[i]]
				}
			else # Wow, yet another format! It's either from the distant past or distant future.
				raise ::Msf::DBImportError.new("Unknown format for XML attributes. Please check your Nokogiri version.")
			end
			return attr_pairs
		end

		def end_document
			block = @block
			unless @state[:current_tag].empty?
				missing_ends = @state[:current_tag].keys.map {|x| "'#{x}'"}.join(", ")
				msg = "Warning, the provided file is incomplete, and there may be missing\n"
				msg << "data. The following tags were not closed: #{missing_ends}."
				db.emit(:warning,msg,&block)
			end
		end

	end

end
end
