require 'msf/core'
require 'msf/base'
require 'msf/ui'

require 'rex/io/bidirectional_pipe'

require 'msf/ui/gtk2/treeviewtooltips'
require 'msf/ui/gtk2/controls'
require 'msf/ui/gtk2/app'
require 'msf/ui/gtk2/about'
require 'msf/ui/gtk2/frame'
require 'msf/ui/gtk2/assistant'
require 'msf/ui/gtk2/dialogs'
require 'msf/ui/gtk2/window'
require 'msf/ui/gtk2/preferences'
require 'msf/ui/gtk2/meterpreter'
require 'msf/ui/gtk2/console'
require 'msf/ui/gtk2/search'
require 'msf/ui/gtk2/opcode'

require 'msf/ui/gtk2/framework_event_manager'

module Msf
module Ui
	module Gtk2

	###
	#
	# This class implements a user interface driver on a gtk2 interface.
	#
	###
	class Driver < Msf::Ui::Driver
		
		# main view
		attr_accessor :session_tree, :module_tree, :job_tree, :log_text, :module_model
		attr_accessor :module_completion, :main, :tips
		
		include Msf::Ui::Gtk2::FrameworkEventManager

		ConfigCore  = "framework/core"
		ConfigGroup = "framework/ui/gtk2"

		#
		# The default resource directory for msfgui
		#
		DefaultResourceDirectory = Msf::Config.data_directory + File::SEPARATOR + "msfgui"
		
		DefaultConfigDirectory = Msf::Config.config_directory + File::SEPARATOR
		
		#
		# Initializes a gtk2 driver instance
		#
		def initialize(opts = {})
			# Call the parent
			super()

			# Set the passed options hash for referencing later on.
			self.opts = opts

			# Initialize configuration
			Msf::Config.init

			# Initialize logging
			initialize_logging

			# Create the gtk2driver global
			$gtk2driver = self

			# Init GTK2
			Gtk.init

			# Initialize the splash screen
			@splash = Msf::Ui::Gtk2::MySplash.new()
			done_splash = false
			
			Gtk.idle_add do 
				if(done_splash)
					self.framework = Msf::Simple::Framework.create
					@gtk2app = Msf::Ui::Gtk2::MyApp.new()
					@gtk2app.window.show
					@splash.destroy
					register_event_handlers
					false
				else
					# Queue a redraw and let the main window start
					@splash.queue_draw
					done_splash = true
					true
				end
			end

		end

		#
		# Starts the main gtk2 loop
		#
		def run
			ilog("msfgui has been started", LogSource)
			Gtk.main
			true
		end

		#
		# Returns the local directory that will hold the files to be serviced.
		#
		def resource_directory
			opts['ResourceDirectory'] || DefaultResourceDirectory
		end


		#
		# Returns the local directory that will hold the files to be serviced.
		#
		def config_directory
			opts['ConfigDirectory'] || DefaultConfigDirectory
		end
		
		#
		# Saves configuration for MsfAssistant.
		#
		def save_config
			# Build out the assistant config group
			group = {}

			if (active_module)
				group['ActiveModule'] = active_module.fullname
			end

			# Save it
			begin
				Msf::Config.save(
				ConfigGroup => group)
			rescue
				MsfDialog::Error.new(self, "Failed to save config file :  #{$!}")
			end
		end

		#
		# Returns a new Gdk::Pixbuf object
		#
		def get_icon(name)
			path = get_image(name) + ".gz"
			fd   = File.open(path, "rb")
			buff = fd.read( File.size(path) )
			fd.close 
			
			Gdk::Pixbuf.new(Rex::Text.ungzip(buff).split("\n"))
		end

		#
		# Returns only pics
		#
		def get_image(name)
			return File.join(resource_directory, 'pix', name)
		end


		#
		# Adds text to the main logging screen
		#
		def append_log_view(data)
			data.gsub!(/[\x80-\xff\x00]/, '?')
			data = Time.now.strftime("%H:%M:%S") + " - " + data

			return if not self.log_text

			view = self.log_text
			buff = view.buffer

			if (not buff.get_mark('end_mark'))
				buff.create_mark('end_mark', buff.end_iter, false)
			end

			buff.insert(buff.end_iter, data)
			buff.move_mark('end_mark', buff.end_iter)
			view.scroll_mark_onscreen(buff.get_mark('end_mark'))
		end


		#
		# The framework instance associated with this driver.
		#
		attr_reader   :framework
		
		#
		# The active module associated with the driver.
		#
		attr_accessor :active_module, :exploit
		attr_writer   :framework # :nodoc:
		attr_accessor :opts      # :nodoc:

		#
		# Initializes logging for the Gtk2 driver.
		#
		def initialize_logging
			level = (opts['LogLevel'] || 0).to_i

			Msf::Logging.enable_log_source(LogSource, level)
		end

	end

	end
end
end
