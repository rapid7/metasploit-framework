module Lab
module Controllers
module VirtualBoxController

	def self.running_list
		vm_names_and_uuids = `VBoxManage list runningvms`.split("\n")
		4.times { vm_names_and_uuids.shift }

		vm_names = []
		vm_names_and_uuids.each do |entry|
			vm_names << entry.split('"')[1]
		end
		
		return vm_names
	end

	def self.dir_list(basepath=nil)
		vm_list = Find.find(basepath).select { |f| f =~ /\.xml$/ }
	end
end
end
end
