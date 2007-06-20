module Msf
  module Ui
    module Gtk2

      ##
      # This class help us to wait the next release of ruby-libglade2 package
      ##
      class GladeXML < GladeXML
        def connect(source, target, signal, handler, data, after = false)
          @handler_proc ||= Proc.new{}
          handler = canonical_handler(handler)
          if target
            signal_proc = target.method(handler)
          else
            signal_proc = @handler_proc.call(handler)
          end

          if after
            sig_conn_proc = source.method(:signal_connect_after)
          else
            sig_conn_proc = source.method(:signal_connect)
          end

          if signal_proc
            guard_source_from_gc(source)
            case signal_proc.arity
            when 0
              sig_conn_proc.call(signal) {signal_proc.call}
            else
              sig_conn_proc.call(signal, &signal_proc)
            end
          elsif $DEBUG
            puts "Undefined handler: #{handler}"
          end
        end

        def guard_source_from_gc(source)
          return if source.nil?
          @sources ||= {}
          @sources[source.object_id] = source

          source.signal_connect("destroy") do |object|
            @sources.delete(object.object_id)
          end

          # To get the parent window of the source as a ruby object.
          # Ruby/GTK keeps the Window objects on the memory to prevend from GC.
          parent = source.parent
          while parent
            parent = parent.parent
          end
        end
      end

      ##
      # This class help us to retreive all glade widgets and place them in your user instance
      # like @windows, @widget, ...
      ##

      class MyGlade
        include Msf::Ui::Gtk2::MyControls

        def initialize(root)
          # Give the glade file and instance the glade object
          file_glade = File.join(driver.resource_directory, 'msfgui.glade')
          glade = GladeXML.new(file_glade, root) { |handler|method(handler) }

          # For all widget names, instance a variable
          glade.widget_names.each do |name|
            begin
              instance_variable_set("@#{name}".intern, glade[name])
            rescue
            end
          end
        end
      end

      ##
      # This is the main class
      ##
      class MyApp < MyGlade

        include Msf::Ui::Gtk2::MyControls

        def initialize
          # console_style = File.join(driver.resource_directory, 'style', 'main.rc')
          # Gtk::RC.parse(console_style)

          super('window')

          # Set a default icon for all widgets
          Gtk::Window.set_default_icon(driver.get_icon('msfwx.xpm'))
          @window.set_icon(driver.get_icon('msfwx.xpm'))

          # Set a title with the version
          @window.set_title("msfgui v#{Msf::Framework::Version}")

          # Destroy
          @window.signal_connect('destroy') { Gtk.main_quit }

          # Default size
          # @window.set_default_size(1024, 768)

          # Defaults policies for Gtk::ScrolledWindow
          @scrolledwindow_module.set_policy(Gtk::POLICY_AUTOMATIC, Gtk::POLICY_AUTOMATIC)
          @scrolledwindow_jobs.set_policy(Gtk::POLICY_AUTOMATIC, Gtk::POLICY_AUTOMATIC)
          @scrolledwindow_session.set_policy(Gtk::POLICY_AUTOMATIC, Gtk::POLICY_AUTOMATIC)
          @scrolledwindow_information.set_policy(Gtk::POLICY_AUTOMATIC, Gtk::POLICY_AUTOMATIC)
          @scrolledwindow_logs.set_policy(Gtk::POLICY_AUTOMATIC, Gtk::POLICY_AUTOMATIC)

          # Logs Buffer
          @buffer = Gtk::TextBuffer.new
          @viewlogs.set_buffer(@buffer_logs)
          @viewlogs.set_editable(false)
          @viewlogs.set_cursor_visible(false)

          # Sessions Tree
          @session_tree = MySessionTree.new(@treeview_session)

          # Target Tree
          @job_tree = MyJobTree.new(@treeview2)

          # Module Tree
          @module_tree = MyModuleTree.new(@treeview1, @viewmodule)

          # Tooltips
          tooltips = Gtk::Tooltips.new

          # Configure the window handles for easy reference
          $gtk2driver.main = @window
          $gtk2driver.session_tree = @session_tree
          $gtk2driver.job_tree = @job_tree
          $gtk2driver.module_tree = @module_tree
          $gtk2driver.log_text = @viewlogs
          $gtk2driver.tips = tooltips

          # Initialize the search class
          ModuleSearch.new(@search_entry, @search_button, @search_cancel_button)

          # Focus on the search widget
          @search_entry.can_focus = true
          @search_entry.grab_focus

          # Update the StatusBar with all framework modules
          refresh()
        end

        #
        # Signal to refresh the treeview module
        #
        def on_refresh_activate
          refresh()
        end

        #
        # Bye bye
        #
        def on_leave_activate
          Gtk.main_quit
        end

        #
        # Actions for OpCodes/Stats
        #
        def on_stats_activate
          MsfOpcode::Stats.new()
        end

        #
        # Actions for OpCodes/Locales
        #
        def on_locales_activate
          MsfOpcode::Locales.new()
        end

        #
        # Actions for OpCodes/Metatypes
        #
        def on_metatypes_activate
          MsfOpcode::Metatypes.new()
        end

        #
        # Actions for OpCodes/Groups
        #
        def on_groups_activate
          MsfOpcode::Groups.new()
        end

        #
        # Actions for OpCodes/Types
        #
        def on_types_activate
          MsfOpcode::Types.new()
        end

        #
        # Actions for OpCodes/Platforms
        #
        def on_platforms_activate
          MsfOpcode::Platforms.new()
        end

        #
        # Actions for OpCodes/Modules
        #
        def on_modules_activate
          MsfOpcode::Modules.new()
        end

        #
        # Actions for OpCodes/Search
        #
        def on_search_activate
        end

        #
        # Action for "Window/Logs" menu
        #
        def on_logs_activate
          MsfWindow::Logs.new
        end

        #
        # The About Dialog
        #
        def on_about_activate
          ad = MyAbout.new(@window)
          ad.signal_connect('response'){ ad.destroy }
          ad.show
        end

        #
        # Call the refresh method to reload all module
        #
        def refresh
          @module_tree.refresh
          context_id = @statusbar.get_context_id("update")
          @statusbar.push(
          context_id,
          "Loaded " +
          framework.stats.num_exploits.to_s + " exploits, " +
          framework.stats.num_payloads.to_s + " payloads, " +
          framework.stats.num_encoders.to_s + " encoders, " +
          framework.stats.num_nops.to_s + " nops, and " +
          framework.stats.num_auxiliary.to_s + " auxiliary"
          )
        end
      end

    end
  end
end
