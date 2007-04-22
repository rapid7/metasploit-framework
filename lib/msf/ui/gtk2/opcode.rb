module Msf
module Ui
module Gtk2
	
require 'rex'
require 'rex/ui'
require 'rex/exploitation/opcodedb'

##
# Gtk2 Interface for msfopcode
##

#
# Skeleton for opcodes stuff
#
class SkeletonOpcode < Gtk::Dialog
	
	attr_accessor :sw
	
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
		
		@hbox = Gtk::HBox.new(false, 10)
		self.vbox.pack_start(@hbox, true, true, 0)
		
		# ScrolledWindow
		@sw = Gtk::ScrolledWindow.new
		@sw.set_policy(Gtk::POLICY_AUTOMATIC, Gtk::POLICY_AUTOMATIC)
		@hbox.pack_start(@sw)
	end
end

class MsfOpcode
	# Create the opcode client instance
	$client = Rex::Exploitation::OpcodeDb::Client.new
	
	class Stats < Msf::Ui::Gtk2::SkeletonOpcode
		def initialize
			super("Statistics", nil)
			self.set_default_size(500, 230)

			stats = $client.statistics
			
			textview = Gtk::TextView.new
			textbuffer = Gtk::TextBuffer.new
			sw.add(textview)
			
			textbuffer.set_text(
						"\n" +
						"Last Updated             : #{stats.last_update.to_s}\n" +
						"Number of Opcodes        : #{stats.opcodes}\n" +
						"Number of Opcode Types   : #{stats.opcode_types}\n" +
						"Number of Platforms      : #{stats.platforms}\n" +
						"Number of Architectures  : #{stats.architectures}\n" +
						"Number of Modules        : #{stats.modules}\n" +
						"Number of Module Segments: #{stats.module_segments}\n" +
						"Number of Module Imports : #{stats.module_imports}\n" +
						"Number of Module Exports : #{stats.module_exports}\n\n")
						
			textview.set_buffer(textbuffer)
			textview.set_editable(false)
			textview.set_cursor_visible(false)
			
			show_all and run
			destroy
		end
	end
	
	class Modules < Msf::Ui::Gtk2::SkeletonOpcode
		def initialize
			super("Modules", nil)
			
			show_all and run
			destroy
		end
	end
end

end
end
end
