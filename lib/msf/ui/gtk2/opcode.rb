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
		
		L_COMBO_TEXT_COLUMN	= 0
		L_COMBO_MODEL		= 1
		L_COMBO_HAS_ENTRY	= 2
		L_COMBO_EDITABLE	= 3
		L_COMBO_TEXT		= 4
		L_REMOVE		= 5
		L_ADD			= 6
		
		def initialize
			comment = "information about imports, exports, segments, and specific module attributes "
			
			# call the parent
			super("Modules", comment)
			
			export = Gtk::CheckButton.new("Include module export information")
			import = Gtk::CheckButton.new("Include module import information")
			segment = Gtk::CheckButton.new("Include module segment information")
			detail = Gtk::CheckButton.new("Display detailed output")
			
			stuff.pack_start(export, false, false, 0)
			stuff.pack_start(import, false, false, 0)
			stuff.pack_start(segment, false, false, 0)
			stuff.pack_start(detail, false, false, 0)
			
						
			@model = create_model
			@locale_treeview = Gtk::TreeView.new(@model)
			stuff.pack_start(@locale_treeview, true, true, 0)
			
			create_renderer()
			
			show_all and run
			destroy
		end
		
		#
		# Create model for the treeview
		#
		def create_model
			store = Gtk::ListStore.new(	Integer,        	# L_COMBO_TEXT_COLUMN
			   				Gtk::ListStore, 	# L_COMBO_MODEL
							TrueClass,      	# L_COMBO_HAS_ENTRY
							TrueClass,      	# L_COMBO_EDITABLE
							String,         	# L_COMBO_TEXT
							Gdk::Pixbuf,	 	# L_REMOVE
							Gdk::Pixbuf)		# L_ADD
			
			combo_model = create_combo
			iter = store.append
			iter[L_COMBO_MODEL] = combo_model
			iter[L_COMBO_HAS_ENTRY] = false
			iter[L_COMBO_EDITABLE] = true
			iter[L_COMBO_TEXT] = combo_model.get_iter("0")[0]
			iter[L_REMOVE] = self.render_icon(Gtk::Stock::REMOVE, Gtk::IconSize::BUTTON, "icon")
			iter[L_ADD] = self.render_icon(Gtk::Stock::ADD, Gtk::IconSize::BUTTON, "icon1")
			
			return store
		end
		
		#
		# Create combo for locales selection
		#
		def create_combo
			# Model for Gtk::Combo
			model_locale = Gtk::ListStore.new(String)
			
			# Add iter to Gtk::Combo
			$client.locales.each do |locale|
				iter = model_locale.append
				iter[0] = locale.name
			end
			
			return model_locale
		end
		
		#
		# Renderer & Column
		#
		def create_renderer
			
			# Renderer for combo Box
			renderer = Gtk::CellRendererCombo.new
			
			# Signal for combo box
			renderer.signal_connect("edited") do |renderer, path, text|
				@model.get_iter(path)[L_COMBO_TEXT] = text
			end

			# Column for combo box
			column = Gtk::TreeViewColumn.new("Select your locale to filter :", renderer,
							       :text_column 	=> L_COMBO_TEXT_COLUMN,
							       :model 		=> L_COMBO_MODEL,
							       :has_entry 	=> L_COMBO_HAS_ENTRY,
							       :editable 	=> L_COMBO_EDITABLE,
							       :text 		=> L_COMBO_TEXT)
			column.sizing = Gtk::TreeViewColumn::FIXED
			column.fixed_width = 450
			column.pack_start(renderer, false)
			
			# renderer for pixbuf
			renderer_remove = Gtk::CellRendererPixbuf.new
			renderer_add = Gtk::CellRendererPixbuf.new
			
			# Column for pixbuf
			column_pixbuf = Gtk::TreeViewColumn.new
			column_pixbuf.pack_start(renderer_remove, false)
			column_pixbuf.set_cell_data_func(renderer_remove) do |column, cell, model, iter|
				cell.pixbuf = iter[L_REMOVE]
			end
			column_pixbuf.pack_start(renderer_add, false)
			column_pixbuf.set_cell_data_func(renderer_add) do |column, cell, model, iter|
				cell.pixbuf = iter[L_ADD]
			end			
			
			# Add columns
			@locale_treeview.append_column(column)
			@locale_treeview.append_column(column_pixbuf)
		end
	end
end

end
end
end
