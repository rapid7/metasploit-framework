module Lab
module Controllers
module RemoteWorkstationController

	def self.running_list(user, host)
		user.gsub!(/(\W)*/, '')
		host.gsub!(/(\W)*/, '')

		remote_cmd = "ssh #{user}@#{host} \"vmrun list nogui\""
		vm_list = `#{remote_cmd}`.split("\n")
		vm_list.shift

		return vm_list
	end

	def self.dir_list(basepath=nil)
		vm_list = Find.find(basepath).select { |f| f =~ /\.vmx$/ }
		return vm_list
	end
end
end
end
