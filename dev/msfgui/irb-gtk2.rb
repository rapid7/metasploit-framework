#!/usr/bin/env ruby
#
# This is a basic irb interface using the Gtk2 GUI library
#

msfbase = File.symlink?(__FILE__) ? File.readlink(__FILE__) : __FILE__
$:.unshift(File.join(File.dirname(msfbase), 'lib'))

require 'gtk2'
require 'irb'
require 'rex'

class Console < Gtk::Window
	
	require 'rex/io/bidirectional_pipe'
	
	@@offset = 0
	
	def initialize
		super()
		
		# Layout stuff
		set_default_size(500, 400)
		set_border_width(10)
		
		# Skeleton ;-)
		vbox = Gtk::VBox.new(false, 5)
		add(vbox)
		
		@buffer = Gtk::TextBuffer.new
		@textview = Gtk::TextView.new(@buffer)
		scrolled_window = Gtk::ScrolledWindow.new
		scrolled_window.add(@textview)
		vbox.pack_start(scrolled_window, true, true, 5)
		scrolled_window.set_policy(Gtk::POLICY_AUTOMATIC, Gtk::POLICY_AUTOMATIC)		
		
		signal_connect('destroy') do 
			Gtk.main_quit
		end
		
		signal_connect('key_press_event') do |edit, event|
			if event.keyval == Gdk::Keyval::GDK_Return
				catch_text
			end
		end
		
		# Create the pipe interface
		@pipe = Rex::IO::BidirectionalPipe.new
		
		# Start the session interaction
		@t_run = Thread.new do
			IRB.init_config(nil)
			IRB.conf[:USE_READLINE] = false
			IRB.init_error
			irb = IRB::Irb.new(IRB::WorkSpace.new())
			IRB.conf[:MAIN_CONTEXT] = irb.context
			irb.eval_input
		end
		
		# Create a subscriber with a callback for the UI
		@sid = @pipe.create_subscriber_proc() do |data|
			@buffer.insert(@buffer.end_iter, Rex::Text.to_utf8(data))
			@buffer.move_mark('end_mark', @buffer.end_iter)
			@textview.scroll_mark_onscreen(@buffer.get_mark('end_mark'))				
		end
		
		show_all
	end
	
	def put_text(text = nil)
		puts text if text
	end
	
	def catch_text
		start = @buffer.get_iter_at_offset(@@offset)
		puts @buffer.get_text(nil, @buffer.end_iter)
		@buffer.insert(@buffer.end_iter,"\n")
		if (not @buffer.get_mark('end_mark'))
			@buffer.create_mark('end_mark', @buffer.end_iter, false)
		end
		@@offset = @buffer.end_iter.offset
	end
end

Console.new
Gtk.main
