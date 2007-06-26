module Msf
  module Ui
    module Gtk2

      ###
      #
      # Classic console herited from Gtk::Window
      #
      ###
      class SkeletonConsole < Gtk::Window
        require 'rex/io/bidirectional_pipe'
        include Msf::Ui::Gtk2::MyControls

        ID_SESSION, PEER, PAYLOAD, O_SESSION, O_BUFFER = *(0..5).to_a

        @@offset = 0

        def initialize(iter)
          # Style
          console_style = File.join(driver.resource_directory, 'style', 'console.rc')
          Gtk::RC.parse(console_style)

          # Call the parent
          super(Gtk::Window::TOPLEVEL)

          # initialize the session and buffer vars from the iter sessions tree
          @session = iter[O_SESSION]
          @buffer = iter[O_BUFFER]

          # Layout stuff
          self.set_default_size(500, 400)
          self.set_border_width(10)

          # Set title with the tunnel peer
          self.set_title(@session.tunnel_peer)

          # Add a vertical box to the window
          vbox = Gtk::VBox.new(false, 5)
          self.add(vbox)

          # Setup text view
          @textview = Gtk::TextView.new
          scrolled_window = Gtk::ScrolledWindow.new
          scrolled_window.add(@textview)
          vbox.pack_start(scrolled_window, true, true, 5)
          scrolled_window.set_policy(Gtk::POLICY_AUTOMATIC, Gtk::POLICY_AUTOMATIC)

          # Setup text buffer
          @textview.set_buffer(@buffer)
          @textview.editable = true
          @textview.set_cursor_visible(true)
          @buffer.create_mark('end_mark', @buffer.end_iter, false)

          # Setup button close
          hbox = Gtk::HButtonBox.new
          hbox.layout_style = Gtk::ButtonBox::END
          button = Gtk::Button.new(Gtk::Stock::CLOSE)
          button.signal_connect("clicked") do
            close_console
          end

          # Pack
          hbox.pack_end(button, false, false, 5)
          vbox.pack_start(hbox, false, false, 0)

          # Signal for the Return key pressed
          signal_connect('key_press_event') do |edit, event|
            on_key_pressed(event)
          end

          # Create the pipe interface
          @pipe = Rex::IO::BidirectionalPipe.new

          # Start the session interaction
          @t_run = Thread.new do
            @session.interact(@pipe, @pipe)
          end

          # Create a subscriber with a callback for the UI
          @sid = @pipe.create_subscriber_proc() do |data|
            insert_text(Rex::Text.to_utf8(data))
          end

          # Display all
          self.show_all

        end #intialize

        #
        # update access
        #
        def update_access
          last_access = Time.now
        end

        #
        # Send command to bidirectionnal_pipe
        #
        def send_cmd(cmd)
          update_access

          # Write the command plus a newline to the input
          @pipe.write_input(cmd + "\n")
        end

        #
        # Just close the console, not kill !
        #
        def close_console
          self.destroy
        end

        ###########
        protected #
        ###########

        #
        # Catch the text from the textview
        #
        def catch_text
          start = @buffer.get_iter_at_offset(@@offset)
          cmd = @buffer.get_text(start, @buffer.end_iter)
          send_cmd(cmd)
          insert_text("\n")

          if (not @buffer.get_mark('end_mark'))
            @buffer.create_mark('end_mark', @buffer.end_iter, false)
          end
          @@offset = @buffer.end_iter.offset
        end

        #
        # Insert the text into the buffer
        #
        def insert_text(text)
          # get the actual offset
          start = @buffer.get_iter_at_offset(@@offset)

          @buffer.insert(@buffer.end_iter, text)
          if (not @buffer.get_mark('end_mark'))
            @buffer.create_mark('end_mark', @buffer.end_iter, false)
          end
          @@offset = @buffer.end_iter.offset
          @textview.scroll_mark_onscreen(@buffer.get_mark('end_mark'))
        end

        #
        # A key pressed handler
        #
        def on_key_pressed(event)

          # Enter key
          if event.keyval == Gdk::Keyval::GDK_Return
            catch_text()

            # Backspace key
          elsif event.keyval == Gdk::Keyval::GDK_BackSpace
            iter = @buffer.end_iter
            if iter.offset == @@offset
              return true
            else
              return false
            end

            # Delete key
          elsif event.keyval == Gdk::Keyval::GDK_Delete
            iter = @buffer.end_iter
            if iter.offset == @@offset
              return true
            else
              return false
            end
            
          end

        end

      end # SkeletonConsole

      ###
      #
      # This class surcharge the Rex::IO::BidirectionalPipe *original* behaviour
      #
      ###
      class GtkConsolePipe < Rex::IO::BidirectionalPipe
        def prompting?
          false
        end
      end

    end
  end
end
