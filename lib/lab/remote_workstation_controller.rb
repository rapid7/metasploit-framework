module Lab
module Controllers
module RemoteWorkstationController

	def self.workstation_running_list(user,host)
		vm_list = `ssh #{user}@#{host} vmrun list nogui`.split("\n")
		vm_list.shift

		return vm_list
	end

	def self.workstation_dir_list(basepath=nil)
		vm_list = Find.find(basepath).select { |f| f =~ /\.vmx$/ }

		return vm_list
	end
end
end
end
