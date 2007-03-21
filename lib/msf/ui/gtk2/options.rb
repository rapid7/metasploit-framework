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
		self.title = title
		
		model = create_model(items)
		treeview = Gtk::TreeView.new(model)
		
		hbox = Gtk::HBox.new(false, 10)
		
		# ScrolledWindow
		sw = Gtk::ScrolledWindow.new
		sw.set_policy(Gtk::POLICY_NEVER, Gtk::POLICY_AUTOMATIC)
		hbox.pack_start(sw)
		sw.add(treeview)
		
		renderer = Gtk::CellRendererText.new
		column = Gtk::TreeViewColumn.new('Select an item', renderer, 'text' => 0)
		column.pack_start(renderer, false)
		treeview.append_column(column)
		
		self.vbox.pack_start(hbox)
		
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
		puts iter[0]
	end
end

class MsfOptions
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
end

end
end
end
