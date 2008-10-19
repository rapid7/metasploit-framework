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

        ###
        #
        # Basic command history class
        #
        ###
        class History

          def initialize
            @history = [""]
            @position = @history.length - 1
          end

          #
          # Get previous command in history array
          #
          def prev(current)
            l = current
            l = l[0,1] if (l.length > 0 and l[0,1] == '\n')
            l = l[-1,1] if (l.length > 0 and l[-1,1] == '\n')
            if (@position > 0)
              if (@position == (@history.length - 1))
                @history[@history.length - 1] = l
              end
              @position = @position - 1
              return @history[@position]
            end
            return current
          end

          #
          # Get next command in history array
          #
          def next(current)
            if (@position < @history.length - 1)
              @position = @position + 1
              return @history[@position]
            end
            return current
          end

          #
          # Append a new command to history
          #
          def append(cmd)
            @position = @history.length - 1
            return if cmd.length == 0
            if ( (@position == 0) or (@position > 0 and cmd != @history[@position - 1]) )
              @history[@position] = cmd
              @position = @position + 1
              @history.push('')
            end
          end

        end

        ID_SESSION, PEER, TYPE, O_SESSION, O_BUFFER = *(0..5).to_a
        @@offset = 0

        attr_accessor :type, :button_close

        #
        # Init the SkeletonConsole class
        #
        def initialize(iter)
          # Style
          console_style = File.join(driver.resource_directory, 'style', 'console.rc')
          Gtk::RC.parse(console_style)

          # Call the parent
          super(Gtk::Window::TOPLEVEL)

          # initialize the session var from the iter sessions tree
          @session = iter[O_SESSION]

          # Layout stuff
          self.set_default_size(500, 400)
          self.set_border_width(10)

          # Set title with the tunnel peer
          self.set_title(@session.tunnel_peer)

          # Add a vertical box to the window
          vbox = Gtk::VBox.new(false, 5)
          self.add(vbox)

          # Setup text view and buffer
          @textview = Gtk::TextView.new
          if iter[O_BUFFER].nil?
            @buffer = Gtk::TextBuffer.new
            iter[O_BUFFER] = @buffer
          else
            @buffer = iter[O_BUFFER]
          end
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
          @button_close = Gtk::Button.new(Gtk::Stock::CLOSE)

          # Pack
          hbox.pack_end(@button_close, false, false, 5)
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

          # Init an history object
          @historic = History.new()

          # Init the prompt variable with the session type
          @type = @session.type

          # Display all
          self.show_all

        end #intialize

        #
        # Send command to bidirectionnal_pipe
        #
        def send_cmd(cmd)
          # What time is it ?
          # update_access

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
        # update access
        #
        def update_access
          last_access = Time.now
        end

        #
        # meterpreter prompt
        #
        def prompt
          null_prompt = ""
          meta_prompt = "meterpreter >> "
          if (@type == "meterpreter")
            @buffer.insert(@buffer.end_iter, meta_prompt)
          else
            @buffer.insert(@buffer.end_iter, null_prompt)
          end
          @@offset = @buffer.end_iter.offset
        end

        #
        # Get the current line
        #
        def current_line
          # get the actual offset
          start = @buffer.get_iter_at_offset(@@offset)

          # get the command
          line = @buffer.get_text(start, @buffer.end_iter)

          return line
        end

        #
        # Replace the current active line with another line
        #
        def replace(line)
          # get the actual offset
          start = @buffer.get_iter_at_offset(@@offset)

          # Delete all
          @buffer.delete(start, @buffer.end_iter)

          # Save the new offset
          @@offset = @buffer.end_iter.offset

          # insert the old command
          @buffer.insert(@buffer.end_iter, line)
        end

        #
        # Catch the text from the textview
        #
        def catch_text
          # get the actual offset
          start = @buffer.get_iter_at_offset(@@offset)

          # get the command
          cmd = @buffer.get_text(start, @buffer.end_iter)

          # Save the command to the history object
          @historic.append(cmd)

          # Write the command to our pipe
          send_cmd(cmd)

          # Add a return line to our buffer
          insert_text("\n")

          # Call the prompt
          prompt()

          # Create the mark tag if not exist
          if (not @buffer.get_mark('end_mark'))
            @buffer.create_mark('end_mark', @buffer.end_iter, false)
          end

          # Save our offset
          @@offset = @buffer.end_iter.offset
        end

        #
        # Insert the text into the buffer
        #
        def insert_text(text)
          # Create the mark tag if not exist
          @buffer.insert(@buffer.end_iter, text)
          if (not @buffer.get_mark('end_mark'))
            @buffer.create_mark('end_mark', @buffer.end_iter, false)
          end

          # Save our offset
          @@offset = @buffer.end_iter.offset

          # Scrolled the view until the end of the buffer
          @textview.scroll_mark_onscreen(@buffer.get_mark('end_mark'))
        end

        #
        # A key pressed handler
        #
        def on_key_pressed(event)

          # Enter key
          if (event.keyval == Gdk::Keyval::GDK_Return)
            catch_text()

            # Backspace key
          elsif (event.keyval == Gdk::Keyval::GDK_BackSpace)
            iter = @buffer.end_iter
            if iter.offset == @@offset
              return true
            else
              return false
            end

            # Delete key
          elsif (event.keyval == Gdk::Keyval::GDK_Delete)
            iter = @buffer.end_iter
            if iter.offset == @@offset
              return true
            else
              return false
            end

            # Previous command
          elsif (event.keyval == Gdk::Keyval::GDK_Up)
            cmd = @historic.prev(current_line())
            replace(cmd)
            return true

            # Next command
          elsif (event.keyval == Gdk::Keyval::GDK_Down)
            cmd = @historic.next(current_line())
            replace(cmd)
            return true
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