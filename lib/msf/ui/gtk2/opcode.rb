module Msf
module Ui
module Gtk2

require 'rex/exploitation/opcodedb'

##
# Gtk2 Interface for msfopcode
##

#
# Skeleton for opcodes stuff
#
class SkeletonOpcode < Gtk::Dialog
	
	include Msf::Ui::Gtk2::MyControls
	
	attr_accessor :comment, :stuff
	
	def initialize(title, comments)
		super("", $gtk2driver.main, Gtk::Dialog::DESTROY_WITH_PARENT,
			#[ Gtk::Stock::OK, Gtk::Dialog::RESPONSE_NONE ],
			[ Gtk::Stock::CLOSE, Gtk::Dialog::RESPONSE_NONE ])
			
		# Style
		console_style = File.join(driver.resource_directory, 'style', 'opcode.rc')
		Gtk::RC.parse(console_style)
		
		self.border_width = 6
		self.resizable = true
		self.has_separator = true
		self.vbox.spacing = 12
		self.vbox.set_homogeneous(false)
		self.title = title
		self.set_default_size(500, 400)
		
		@comment = Gtk::Label.new
		@comment.set_alignment(0, 0)
		@comment.set_markup("<b>#{comments}</b>")
		self.vbox.pack_start(@comment, false, false, 0)
		
		@stuff = Gtk::VBox.new(false, 10)
		self.vbox.pack_start(@stuff, true, true, 0)
	end
end

#
# Gtk2 Interface for Metasploit Opcodes database
#
class MsfOpcode
	
	# Create the opcode client instance
	$client = Rex::Exploitation::OpcodeDb::Client.new
	
	#
	# Opcodes statistics
	#
	class Stats < Msf::Ui::Gtk2::SkeletonOpcode
		
		def initialize
			comment = "Current database statistics :"
			
			# Call the parent
			super("Statistics", comment)
			
			self.set_default_size(500, 230)
			
			stats = $client.statistics
			
			textview = Gtk::TextView.new
			textbuffer = Gtk::TextBuffer.new
			stuff.pack_start(textview, true, true, 0)
			
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
	
	#
	# Opcodes locales
	#
	class Locales < Msf::Ui::Gtk2::SkeletonOpcode
		def initialize
			comment = "Locales currently supported by the database:"
			
			# call the parent
			super("Locales", comment)
			
			self.set_default_size(500, 230)
			
			textview = Gtk::TextView.new
			textbuffer = Gtk::TextBuffer.new
			stuff.pack_start(textview, true, true, 0)
			
			locales = "\n"
			$client.locales.each do |locale| 
				locales << " -" + locale.name + "\n"
			end
			
			textbuffer.set_text( locales )
						
			textview.set_buffer(textbuffer)
			textview.set_editable(false)
			textview.set_cursor_visible(false)
			
			show_all and run
			destroy
		end
	end

	#
	# Opcodes meta types
	#
	class Metatypes < Msf::Ui::Gtk2::SkeletonOpcode
		def initialize
			comment = "Opcode meta types currently supported by the database :"
			
			super("Metatypes", comment)
			
			textview = Gtk::TextView.new
			textbuffer = Gtk::TextBuffer.new
			stuff.pack_start(textview, true, true, 0)
			
			mts = "\n"
			$client.meta_types.each do |mt| 
				mts << " - " + mt.name + "\n"
			end
			
			textbuffer.set_text( mts )
						
			textview.set_buffer(textbuffer)
			textview.set_editable(false)
			textview.set_cursor_visible(false)
			
			show_all and run
			destroy
		end
	end
	
	#
	# Opcodes groups
	#
	class Groups < Msf::Ui::Gtk2::SkeletonOpcode
		def initialize
			comment = "Opcode groups currently supported by the database :"
			
			super("Groups", comment)
			
			textview = Gtk::TextView.new
			textbuffer = Gtk::TextBuffer.new
			stuff.pack_start(textview, true, true, 0)
			
			gs = "\n"
			$client.groups.each do |g| 
				gs << " - " + g.name + "\n"
			end
			
			textbuffer.set_text( gs )
						
			textview.set_buffer(textbuffer)
			textview.set_editable(false)
			textview.set_cursor_visible(false)
			
			show_all and run
			destroy
		end
	end

	#
	# Opcodes types
	#
	class Types < Msf::Ui::Gtk2::SkeletonOpcode
		def initialize
			comment = "Lists of the various specific opcode types supported by the database :"
			
			super("Types", comment)
			
			textview = Gtk::TextView.new
			textbuffer = Gtk::TextBuffer.new
			
			scrolled_window = Gtk::ScrolledWindow.new
			scrolled_window.add(textview)
			stuff.pack_start(scrolled_window, true, true, 5)
			scrolled_window.set_policy(Gtk::POLICY_AUTOMATIC, Gtk::POLICY_AUTOMATIC)
			
			tps = "\n"
			$client.types.each do |g| 
				tps << " - " + g.name + "\n"
			end
			
			textbuffer.set_text( tps )
						
			textview.set_buffer(textbuffer)
			textview.set_editable(false)
			textview.set_cursor_visible(false)
			
			show_all and run
			destroy
		end
	end

	#
	# Opcodes Platforms
	#
	class Platforms < Msf::Ui::Gtk2::SkeletonOpcode
		def initialize
			comment = "Supported operating system versions broken down by major version and service pack :"
			
			super("Platforms", comment)
			
			textview = Gtk::TextView.new
			textbuffer = Gtk::TextBuffer.new
			
			scrolled_window = Gtk::ScrolledWindow.new
			scrolled_window.add(textview)
			stuff.pack_start(scrolled_window, true, true, 5)
			scrolled_window.set_policy(Gtk::POLICY_AUTOMATIC, Gtk::POLICY_AUTOMATIC)
			
			ps = "\n"
			$client.platforms.each do |p| 
				ps << " - " + p.name + "\n"
			end
			
			textbuffer.set_text( ps )
						
			textview.set_buffer(textbuffer)
			textview.set_editable(false)
			textview.set_cursor_visible(false)
			
			show_all and run
			destroy
		end
	end	
	
	#
	# Modules Opcodes
	#
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
