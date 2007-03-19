module Msf
module Ui
module Gtk2

##
# Skeleton class for all options stuff
# title = Options title (menu)
# notebook = Gtk::Notebook
##
class SkeletonOption < Gtk::Dialog
	def initialize(title, notebook)
		super("", $gtk2driver.main, Gtk::Dialog::DESTROY_WITH_PARENT,
			[ Gtk::Stock::OK, Gtk::Dialog::RESPONSE_NONE ],
			[ Gtk::Stock::CLOSE, Gtk::Dialog::RESPONSE_NONE ])
		
		self.border_width = 6
		self.resizable = true
		self.has_separator = true
		self.vbox.spacing = 12
		self.title = title
		
		self.vbox.pack_start(notebook)
	end
end

class MsfOptions
	class Preferences < Msf::Ui::Gtk2::SkeletonOption
		def initialize()
			@notebook = Gtk::Notebook.new
			super("Preferences", @notebook)
			
			show_all and run
			destroy
		end
	end
end

end
end
end
