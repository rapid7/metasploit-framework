module Msf
module Ui
module Gtk2

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
		super('window')
		
		# Set a default icon for all widgets
		Gtk::Window.set_default_icon(driver.get_icon('msfwx.xpm'))
		@window.set_icon(driver.get_icon('msfwx.xpm'))
		
		# Set a title with the version
		@window.set_title("MSF Gui v#{Msf::Framework::Version}")
		
		# Destroy
		@window.signal_connect('destroy') { Gtk.main_quit }
		
		# Default size
		# @window.set_default_size(1024, 768)	
		
		# Defaults policies for Gtk::ScrolledWindow
		@scrolledwindow1.set_policy(Gtk::POLICY_AUTOMATIC, Gtk::POLICY_AUTOMATIC)
		@scrolledwindow2.set_policy(Gtk::POLICY_AUTOMATIC, Gtk::POLICY_AUTOMATIC)
		@scrolledwindow3.set_policy(Gtk::POLICY_AUTOMATIC, Gtk::POLICY_AUTOMATIC)
		@scrolledwindow4.set_policy(Gtk::POLICY_AUTOMATIC, Gtk::POLICY_AUTOMATIC)
		@scrolledwindow16.set_policy(Gtk::POLICY_AUTOMATIC, Gtk::POLICY_AUTOMATIC)
		
		# Logs Buffer
		# TODO: currently not used
		@buffer = Gtk::TextBuffer.new
		@viewlogs.set_buffer(@buffer_logs)
		@viewlogs.set_editable(false)
		@viewlogs.set_cursor_visible(false)		
		
		# Sessions Tree
		@session_tree = MySessionTree.new(@treeview_session)		
		
		# Target Tree
		@target_tree = MyTargetTree.new(@treeview2, @session_tree)
		
		# Module Tree
		@module_tree = MyModuleTree.new(@treeview1, @viewmodule, @target_tree, @session_tree)
		
		# Configure the window handles for easy reference
		$gtk2driver.session_tree = @session_tree
		$gtk2driver.target_tree = @target_tree
		$gtk2driver.module_tree = @module_tree
		$gtk2driver.log_text = @viewlogs
		
		# Update the StatusBar with all framework modules
		refresh()
		
		# TODO: Add an hook for binding all links with browser preference
		# Gtk::AboutDialog.set_url_hook do |about, link|
			# puts link
		# end
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
	
	def on_payload_activate
		puts "TODO: Set preferences for the payload choice"
	end
	
	#
	# The About Dialog
	#
	def on_about_activate
		MyAbout.new
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
