module Msf
module Ui
module Gtk2

class Console
	require 'rex/io/bidirectional_pipe'
	
	ID_SESSION, PEER, PAYLOAD, O_SESSION, O_BUFFER = *(0..5).to_a
	
	#
	# Classic console herited from Gtk::Window
	#
	class Basic < Gtk::Window
		include Msf::Ui::Gtk2::MyControls	
		
		def initialize(iter)
			
			# Style
			console_style = File.join(driver.resource_directory, 'style', 'console.rc')
			Gtk::RC.parse(console_style)
			
			super(Gtk::Window::TOPLEVEL)
			
			@session = iter[O_SESSION]
			@buffer = iter[O_BUFFER]
			
			# Layout stuff
			self.set_default_size(500, 400)
			self.set_border_width(10)
			
			# Set title with the tunnel peer
			self.set_title(@session.tunnel_peer)
			
			# Skeleton ;-)
			vbox = Gtk::VBox.new(false, 5)
			self.add(vbox)
			
			@textview = Gtk::TextView.new
			scrolled_window = Gtk::ScrolledWindow.new
			scrolled_window.add(@textview)
			vbox.pack_start(scrolled_window, true, true, 5)
			scrolled_window.set_policy(Gtk::POLICY_AUTOMATIC, Gtk::POLICY_AUTOMATIC)
			
			@cmd_entry = Gtk::Entry.new
			vbox.pack_start(@cmd_entry, false, false, 0)
			
			hbox = Gtk::HButtonBox.new
			hbox.layout_style = Gtk::ButtonBox::END
			button = Gtk::Button.new(Gtk::Stock::CLOSE)
			button.signal_connect("clicked") do
				close_console
			end
			hbox.pack_end(button, false, false, 5)
			vbox.pack_start(hbox, false, false, 0)
			
			@textview.set_buffer(@buffer)
			@textview.editable = false
			@textview.set_cursor_visible(false)
			@buffer.create_mark('end_mark', @buffer.end_iter, false)
			
			# Give focus to Gtk::Entry
			@cmd_entry.can_focus = true
			@cmd_entry.grab_focus()
			
			# Signal
			@cmd_entry.signal_connect('activate') do
				on_cmd_entry_activate
			end
			
			# Create the pipe interface
			@pipe = Rex::IO::BidirectionalPipe.new
			
			# Start the session interaction
			@t_run = Thread.new do 
				@session.interact(@pipe, @pipe)
			end
			
			# Create a subscriber with a callback for the UI
			@sid = @pipe.create_subscriber_proc() do |data|
				@buffer.insert(@buffer.end_iter, Rex::Text.to_utf8(data))
				@buffer.move_mark('end_mark', @buffer.end_iter)
				@textview.scroll_mark_onscreen(@buffer.get_mark('end_mark'))				
			end
			
			#Gtk::RC.parse(console_style)
			
			self.show_all
			
			# Kill the interaction thread
			#@t_run.kill
			
			# Close the pipes
			#@pipe.close
			
		end
		
		#
		# update access
		#
		def update_access
			last_access = Time.now
		end
	
		#
		# Signal for user entry
		#
		def on_cmd_entry_activate
			send_cmd(@cmd_entry.text)
		end
		
		#
		# Send command to bidirectionnal_pipe
		#
		def send_cmd(cmd)
			
			update_access
			
			# Write the command plus a newline to the input
			@pipe.write_input(cmd + "\n")
	
			# Clear the text entry
			@cmd_entry.set_text("")
		end
		
		#
		# Just close the console, not kill !
		#
		def close_console
			self.destroy
		end
	end
	
	#
	# Meterpreter Console
	# TODO: Motivated to code it, hehe ... Ho YESSS ;-)
	#
	class Meterpreter < Gtk::Window
	
		def inititialize
			nil
		end
	end
	
	#
	# VNC Console
	#
	class VNC < Gtk::Window
		
		def initialize
			nil
		end
	end
end



class GtkConsolePipe < Rex::IO::BidirectionalPipe
	def prompting?
		false
	end
end
	
end
end
end

