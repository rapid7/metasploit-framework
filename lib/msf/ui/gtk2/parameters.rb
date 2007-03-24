module Msf
module Ui
module Gtk2

##
# Skeleton class for all options stuff
# title = Options title (menu)
# notebook = Gtk::Notebook
##
class SkeletonOption < Gtk::Dialog
	def initialize(title, items)
		super("", $gtk2driver.main, Gtk::Dialog::DESTROY_WITH_PARENT,
			[ Gtk::Stock::OK, Gtk::Dialog::RESPONSE_NONE ],
			[ Gtk::Stock::CLOSE, Gtk::Dialog::RESPONSE_NONE ])
		
		self.border_width = 6
		self.resizable = true
		self.has_separator = true
		self.vbox.spacing = 12
		self.vbox.set_homogeneous(false)
		self.title = title
		self.set_default_size(500, 400)
		
		model = create_model(items)
		treeview = Gtk::TreeView.new(model)
		treeview.set_size_request(5, 200)
		
		@hbox = Gtk::HBox.new(false, 10)
		
		# ScrolledWindow
		sw = Gtk::ScrolledWindow.new
		sw.set_policy(Gtk::POLICY_NEVER, Gtk::POLICY_AUTOMATIC)
		@hbox.pack_start(sw)
		sw.add(treeview)
		
		renderer = Gtk::CellRendererText.new
		column = Gtk::TreeViewColumn.new('Select an item', renderer, 'text' => 0)
		#column.fixed_width = 20
		column.pack_start(renderer, false)
		treeview.append_column(column)
		
		self.vbox.pack_start(@hbox, false, false, 0)
		@label = Gtk::Label.new("test")
		@frame = Gtk::Frame.new("frame")
		@frame.set_size_request(300, 400)
		@hbox.pack_end(@frame, true, true, 0)
		
		# Signal
		selection = treeview.selection
		selection.mode = Gtk::SELECTION_SINGLE
		selection.signal_connect('changed') do |s|
			selection_changed(s)
		end
	end
	
	def create_model(items)
		store = Gtk::ListStore.new(String)
		
		items.each do |item|
			iter = store.append
			iter[0] = item
		end
		
		return store
	end
	
	def selection_changed(selection)
		iter = selection.selected
		@frame.set_label(iter[0])
	end
end

class MsfParameters
	##
	# Display the preference parameters
	##
	class Preferences < Msf::Ui::Gtk2::SkeletonOption
		def initialize
			menu = ["Exploits", "Payloads"]
			super("Preferences", menu)
			
			show_all and run
			destroy
		end
		
		#
		# Describe the exploits widget
		#
		def w_exploits
		end
		
		#
		# Describe the payloads widget
		#
		def w_payloads
		end
	end
	
	
	##
	# Display the databases parameters
	##
	class Databases < Msf::Ui::Gtk2::SkeletonOption
		def initialize
			menu = ["AutoPOWN", "OPCODES"]
			super("Databases", menu)
			
			show_all and run
			destroy
		end
		
		#
		# Describe the autopown widget
		#
		def w_autopown
		end
		
		#
		# Describe the opcode widget opcodes
		#
		def w_opcode
		end
	end
end

end
end
end
