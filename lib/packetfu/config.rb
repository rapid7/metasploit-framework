
module PacketFu

	# The Config class holds various bits of useful default information for packet creation.
	# If initialized without arguments, the @iface and @pcapfile instance variables are
	# set to the (pcaprub-believed) default interface and "/tmp/out.pcap", respectively.
	#
	# Any number of instance variables can be passed in to the intialize function (as a
	# hash), though only the expected network-related variables will be readable and
	# writeable directly.
	#
	# == Examples
	#
	#   PacketFu::Config.new(:ip_saddr => "1.2.3.4").ip_saddr #=> "1.2.3.4"
	#   PacketFu::Config.new(:foo=>"bar").foo #=> NomethodError: undefined method `foo'...
	#
	# The config() function, however, does provide access to custom variables:
	#
	#   PacketFu::Config.new(:foo=>"bar").config[:foo] #=> "bar"
	#   obj = PacketFu::Config.new(:foo=>"bar")
	#   obj.config(:baz => "bat")
	#   obj.config #=> {:iface=>"eth0", :baz=>"bat", :pcapfile=>"/tmp/out.pcap", :foo=>"bar"}
	class Config
		attr_accessor :eth_saddr,	# The discovered eth_saddr 
			:eth_daddr,							# The discovered eth_daddr (ie, the gateway)
			:eth_src,								# The discovered eth_src in binary form.
			:eth_dst,								# The discovered eth_dst (gateway) in binary form.
			:ip_saddr,							# The discovered ip_saddr
			:ip_src,								# The discovered ip_src in binary form.
			:iface,									# The declared interface.
			:pcapfile								# A declared default file to write to.
	
		def initialize(args={})
			if Process.euid.zero?
				@iface = Pcap.lookupdev || "lo" # In case there aren't any...
			end	
			@pcapfile = "/tmp/out.pcap"
			args.each_pair { |k,v| self.instance_variable_set(("@" + k.to_s).intern,v) }
		end

		# Returns all instance variables as a hash (including custom variables set at initialization).
		def config(arg=nil)
			if arg.nil?
				config_hash = {}
				self.instance_variables.each { |v| config_hash[v.delete("@").intern] = self.instance_variable_get(v) }
				config_hash
			else
				arg.each_pair {|k,v| self.instance_variable_set(("@" + k.to_s).intern, v)}
			end
		end

	end

end