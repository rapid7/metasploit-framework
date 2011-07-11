# This controller was built against: 
# VMware ESX Host Agent 4.1.0 build-348481

module Lab
module Controllers
module RemoteEsxController
		
	# Note that 3.5 was different (vmware-vim-cmd)
	VIM_CMD = 'vim-cmd'.freeze

	def self.dir_list(basepath=nil)
		# Does this method really even make sense for esx?
		return "Unsupported :("
	end

	def self.running_list(user, host)
		user.gsub!(/(\W)*/, '')
		host.gsub!(/(\W)*/, '')

		# first get all registered vms
		registered_vms = self.get_vms(user, host) || []
		running_vms = []

		# now let's see which ones are running
		# TODO:  this is ghetto, would be better not to connect repeatedly
		registered_vms.each do |vm|
			remote_cmd = "ssh #{user}@#{host} \"#{VIM_CMD} vmsvc/power.getstate #{vm[:id]}\""
			raw = `#{remote_cmd}`
			running_vms << vm if raw =~ /Powered on/			
		end

		return running_vms
	end

private 

	def self.get_vms(user, host)
		user.gsub!(/(\W)*/, '')
		host.gsub!(/(\W)*/, '')
		
		vms = [] # array of VM hashes
		remote_cmd = "ssh #{user}@#{host} \"#{VIM_CMD} vmsvc/getallvms | grep ^[0-9] | sed 's/[[:blank:]]\\{3,\\}/ /g'\""
		raw = `#{remote_cmd}`.split("\n")

		raw.each do |line|
			# So effing ghetto
			id_and_name = line.split('[datastore').first
			id = id_and_name.split(' ').first
	
			## TODO - there's surely a better way to do this.
			name_array = id_and_name.split(' ')
			name_array.shift
			name = name_array.join(' ')
			vms << {:id => id, :name => name}
		end
		
		return vms
	end
	
end
end
end
