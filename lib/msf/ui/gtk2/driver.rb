require 'msf/core'
require 'msf/base'
require 'msf/ui'

require 'msf/ui/gtk2/treeviewtooltips'
require 'msf/ui/gtk2/controls'
require 'msf/ui/gtk2/app'
require 'msf/ui/gtk2/about'
require 'msf/ui/gtk2/frame'
require 'msf/ui/gtk2/assistant'
require 'msf/ui/gtk2/dialogs'
require 'msf/ui/gtk2/meterpreter'
require 'msf/ui/gtk2/console'
require 'msf/ui/gtk2/view'
require 'msf/ui/gtk2/search'
require 'msf/ui/gtk2/parameters'
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

        attr_accessor :session_tree, :module_tree, :job_tree, :log_text, :module_model
        attr_accessor :module_completion, :main, :tips

        include Msf::Ui::Gtk2::FrameworkEventManager

        ConfigCore  = "framework/core"
        ConfigGroup = "framework/ui/gtk2"

        #
        # The default resource directory for msfgui
        #
        DefaultResourceDirectory = Msf::Config.data_directory + File::SEPARATOR + "msfgui"

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

          # Initialize attributes
          self.framework = Msf::Simple::Framework.create

          # Create the gtk2driver global
          $gtk2driver = self

          # Init GTK2
          Gtk.init

          # Initialize the Gtk2 application object
          @gtk2app = Msf::Ui::Gtk2::MyApp.new()

          # Register event handlers
          register_event_handlers
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
          Gdk::Pixbuf.new(File.join(resource_directory, 'pix', name))
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

          data = Time.now.strftime("%H:%m:%S") + " " + data

          return if not self.log_text

          view = self.log_text
          buff = view.buffer

          if (not buff.get_mark('end_mark'))
            buff.create_mark('end_mark', buff.end_iter, false)
          end

          buff.insert(buff.end_iter, Rex::Text.to_utf8(data))
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
      	attr_accessor :active_module

        protected

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
