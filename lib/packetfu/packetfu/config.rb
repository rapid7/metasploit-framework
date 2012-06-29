# -*- coding: binary -*-
module PacketFu

	# The Config class holds various bits of useful default information 
	# for packet creation. If initialized without arguments, @iface will be 
	# set to ENV['IFACE'] or Pcap.lookupdev (or lo), and the @pcapfile will
	# be set to "/tmp/out.pcap" # (yes, it's Linux-biased, sorry, fixing 
	# this is a TODO.)
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
				@iface = args[:iface] || ENV['IFACE'] || Pcap.lookupdev || "lo" 
			end	
			@pcapfile = "/tmp/out.pcap"
			args.each_pair { |k,v| self.instance_variable_set(("@#{k}"),v) }
		end

		# Returns all instance variables as a hash (including custom variables set at initialization).
		def config(arg=nil)
			if arg
				arg.each_pair {|k,v| self.instance_variable_set(("@" + k.to_s).intern, v)}
			else
				config_hash = {}
				self.instance_variables.each do |v| 
					key = v.to_s.gsub(/^@/,"").to_sym
					config_hash[key] = self.instance_variable_get(v) 
				end
				config_hash
			end
		end

	end

end
