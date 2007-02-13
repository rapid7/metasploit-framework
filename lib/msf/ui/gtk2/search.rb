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
	# Perform a search throught the module treeview
	#
	
	def search(text)
		found = nil
		filter = Regexp.new(text, Regexp::IGNORECASE)
		$gtk2driver.module_model.each do |model, path, iter|
			if (iter[0][filter])
				found = iter
				puts iter[0]
			end
		end
	end
end

end
end
end
