module Msf
module Ui
module Gtk2

##
# This class describe all search stuff into the module treeview
##
class ModuleSearch
	include Msf::Ui::Gtk2::MyControls
	
	RUNNING, CLEAR = *(0..2).to_a
	
	
	#
	# Initialize all stuff to perform a search
	#
	def initialize(search_entry, search_button, search_cancel_button)
		@search_entry = search_entry
		@search_button = search_button
		@cancel_button = search_cancel_button
		
		@search_button.signal_connect('clicked') do
			search(@search_entry.text)
		end
		
		@cancel_button.signal_connect('clicked') do
			cancel()
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
		
		# Colorize the Gtk::Entry
		state(RUNNING)
		
		# pass the found array to the MyModuleTree and remove all not matched iter
		# and finish by expanding the treeview
		$gtk2driver.module_tree.remove(found)
		$gtk2driver.module_tree.expand
	end
	
	
	#
	# Clean the Gtk::Entry and refresh the modules treeview
	#
	def cancel
		# clear the Gtk::Entry
		@search_entry.set_text("")
		
		# Colorize the Gtk::Entry
		state(CLEAR)
		
		# Refresh the modules treeview
		$gtk2driver.module_tree.refresh
	end
	
	
	#
	# Colorize the Gtk::Entry by state parameter
	#
	def state(state)
		if (state == RUNNING)
			@search_entry.modify_base(Gtk::STATE_NORMAL, Gdk::Color.parse('gray'))
		elsif (state == CLEAR)
			@search_entry.modify_base(Gtk::STATE_NORMAL, Gdk::Color.parse('white'))
		end
	end
end

end
end
end
