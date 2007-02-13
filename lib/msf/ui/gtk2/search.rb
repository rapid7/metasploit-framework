module Msf
module Ui
module Gtk2

##
# This class describe all search stuff into the module treeview
##
class ModuleSearch
	include Msf::Ui::Gtk2::MyControls
	
	#
	# Initialize all stuff to perform a search
	#
	def initialize(search_entry, search_button)
		@search_entry = search_entry
		@search_button = search_button
		
		@search_button.signal_connect('clicked') do
			search(@search_entry.text)
		end
	end
	
	#
	# Perform a search throught the module treeview,
	# and return the array result to MyModuleTree::remove
	#	
	def search(text)
		found = []
		filter = Regexp.new(text, Regexp::IGNORECASE)
		$gtk2driver.module_model.each do |model, path, iter|
			if (not iter[0][filter])
				found.push(iter)
			end
		end
		
		# pass the found array to the MyModuleTree and remove all not matched iter
		$gtk2driver.module_tree.remove(found)
	end
end

end
end
end
