module Msf
module Ui
module Gtk2

require 'rex/exploitation/opcodedb'

require 'rexml/document'

##
# Gtk2 Interface for msfopcode
##

#
# Skeleton for opcodes stuff
#
class SkeletonOpcode < Gtk::Dialog
	
	include Msf::Ui::Gtk2::MyControls
	
	attr_accessor :comment, :stuff
	
	def initialize(title, comments, buttons=[[ Gtk::Stock::CLOSE, Gtk::Dialog::RESPONSE_NONE ]])
		super("", $gtk2driver.main, Gtk::Dialog::DESTROY_WITH_PARENT, *buttons)
			
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
			
			# call the parent
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
			
			# call the parent
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
			
			# call the parent
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
			
			# call the parent
			super("Platforms", comment)
			
			textview = Gtk::TextView.new
			textbuffer = Gtk::TextBuffer.new
			
			scrolled_window = Gtk::ScrolledWindow.new
			scrolled_window.add(textview)
			stuff.pack_start(scrolled_window, true, true, 5)
			scrolled_window.set_policy(Gtk::POLICY_AUTOMATIC, Gtk::POLICY_AUTOMATIC)
			
			ps = "\n"
			$client.platforms.each do |p| 
				ps << " - " + p.desc + "\n"
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
			comment = "information about imports, exports, segments, and specific module attributes "
			
			# Array for the face buttons
			buttons = [ Gtk::Stock::OK, Gtk::Dialog::RESPONSE_OK ], [ Gtk::Stock::CLOSE, Gtk::Dialog::RESPONSE_NONE ]
			
			# call the parent
			super("Modules", comment, buttons)
			self.default_response = Gtk::Dialog::RESPONSE_OK
			
			# Hash to store the global values
			@filter = {}
			
			@collect = {}
			@collect_locales = {}
			@collect_platforms = {}
			@collect_modules = Gtk::TextBuffer.new
			
			@collect['Exports'] = Gtk::CheckButton.new("Include module export information")
			@collect['Imports'] = Gtk::CheckButton.new("Include module import information")
			@collect['Segments'] = Gtk::CheckButton.new("Include module segment information")
			@collect['Detailed'] = Gtk::CheckButton.new("Display detailed output")
			
			stuff.pack_start(@collect['Exports'], false, false, 0)
			stuff.pack_start(@collect['Imports'], false, false, 0)
			stuff.pack_start(@collect['Segments'], false, false, 0)
			stuff.pack_start(@collect['Detailed'], false, false, 0)
			
			# For Locales frame
			frame_locale = Gtk::Frame.new
			stuff.pack_start(frame_locale, false, false, 0)
			@table_locale = Gtk::Table.new(3, 2, true)
			frame_locale.add(@table_locale)
			create_locales
			
			# For Platforms frame
			frame_platforms = Gtk::Frame.new
			stuff.pack_start(frame_platforms, false, false, 0)
			@table_platforms = Gtk::Table.new(3, 2, true)
			frame_platforms.add(@table_platforms)
			create_platforms
			
			# For Modules frame
			frame_modules = Gtk::Frame.new
			stuff.pack_start(frame_modules, false, false, 0)
			@vbox_modules = Gtk::VBox.new(false, 10)
			frame_modules.add(@vbox_modules)
			create_modules(@collect_modules)
			
			signal_connect('response') do |dialog, response_id|
				if response_id == Gtk::Dialog::RESPONSE_OK
					collect()
				end
			end			
			
			show_all and run
			destroy
		end
		
		#
		# Display all supported locales
		#
		def create_locales
			@collect_locales['english'] = Gtk::CheckButton.new("English")
			@collect_locales['french'] = Gtk::CheckButton.new("French")
			@collect_locales['italian'] = Gtk::CheckButton.new("Italian")
			@collect_locales['german'] = Gtk::CheckButton.new("German")
			@table_locale.attach_defaults(@collect_locales['english'], 0, 1, 1, 2)
			@table_locale.attach_defaults(@collect_locales['french'], 0, 1, 2, 3)
			@table_locale.attach_defaults(@collect_locales['italian'], 1, 2, 1, 2)
			@table_locale.attach_defaults(@collect_locales['german'], 1, 2, 2, 3)
		end
		
		#
		# Display all supported platforms
		#		
		def create_platforms
			@collect_platforms['NT'] = Gtk::CheckButton.new("Windows NT")
			@collect_platforms['2000'] = Gtk::CheckButton.new("Windows 2000")
			@collect_platforms['XP'] = Gtk::CheckButton.new("Windows XP")
			@collect_platforms['2003'] = Gtk::CheckButton.new("Windows 2003")
			@table_platforms.attach_defaults(@collect_platforms['NT'], 0, 1, 1, 2)
			@table_platforms.attach_defaults(@collect_platforms['2000'], 0, 1, 2, 3)
			@table_platforms.attach_defaults(@collect_platforms['XP'], 1, 2, 1, 2)
			@table_platforms.attach_defaults(@collect_platforms['2003'], 1, 2, 2, 3)
		end
		
		#
		# Display a Gtk::TextView for modules
		#
		def create_modules(buffer)
			label = Gtk::Label.new(" A comma separated list of module names to filter (Ex: kernel32.dll,user32.dll)")
			label.set_alignment(0, 0)
			@vbox_modules.pack_start(label, false, false, 0)
			textview = Gtk::TextView.new(buffer)
			textview.set_size_request(480, 50)
			@vbox_modules.pack_start(textview, true, true, 0)
		end
		
		#
		# Collect data
		#
		def collect
			
			# For Global option
			@collect.each_pair do |key, value|
				if value.active?
					@filter[key] = true
				end
			end
						
			# For locales
			@filter['LocaleNames'] = ""
			@collect_locales.each_pair do |key, value|
				if value.active?
					@filter['LocaleNames'] = @filter['LocaleNames'] + key
				end
			end
			
			# For platform
			@filter['PlatformNames'] = ""
			@collect_platforms.each_pair do |key, value|
				if value.active?
					@filter['PlatformNames'] = @filter['PlatformNames'] + key
				end
			end
			
			# For module
			@filter['ModuleNames'] = @collect_modules.get_text.split(/,/)
			
			# Perform an XML request
			modules = $client.modules(@filter)
			
			display($client.last_xml)
			
		end
		
		#
		# Display the matched modules
		#
		def display(xml)
			
			# Load XML
			doc = REXML::Document.new(xml)
			
			doc.elements.each("Array/Hash/Entry[@name='name']") do |element| 
				puts element.text
			end
			
			# puts doc.elements["Array/Hash/Entry[@name='name']"].text
			
		end
	end
end

end
end
end
