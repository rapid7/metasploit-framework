module Msf
  module Ui
    module Gtk2

      class MsfWindow

        #
        # This class is dedicated to output auxiliary modules
        #
        class Auxiliary < Msf::Ui::Gtk2::SkeletonBasic

          include Msf::Ui::Gtk2::MyControls

          def initialize(title, data)
            console_style = File.join(driver.resource_directory, 'style', 'console.rc')
            Gtk::RC.parse(console_style)

            # call the parent
            super(title)

            # Define the size and border
            set_default_size(400, 400)
            set_border_width(10)

            # Main hbox
            vbox = Gtk::VBox.new(false, 0)
            add(vbox)

            # Description
            @r_buffer = SkeletonTextBuffer.new()
            @r_view = Gtk::TextView.new(@r_buffer)
            @r_view.set_size_request(400, 70)
            r_sw = Gtk::ScrolledWindow.new()
            r_sw.set_policy(Gtk::POLICY_AUTOMATIC, Gtk::POLICY_AUTOMATIC)
            vbox.pack_start(r_sw, false, false, 0)
            r_sw.add(@r_view)

            # Live log
            @buffer = SkeletonTextBuffer.new
            @view = Gtk::TextView.new(@buffer)
            sw = Gtk::ScrolledWindow.new()
            sw.set_policy(Gtk::POLICY_AUTOMATIC, Gtk::POLICY_AUTOMATIC)
            vbox.pack_start(sw, true, true, 0)
            sw.add(@view)

            append_review(title, data)

            # Return window
            return self
          end

          #
          # Adds text to the main logging screen
          #
          def append_log_view(data)
            data.gsub!(/[\x80-\xff\x00]/, '?')
			
            if (not @buffer.get_mark('end_mark'))
              @buffer.create_mark('end_mark', @buffer.end_iter, false)
            end

            @buffer.insert_with_tags(@buffer.end_iter, Time.now.strftime("%H:%M:%S "), 'forestgreen_bold')
            @buffer.insert_with_tags(@buffer.end_iter, Rex::Text.to_utf8(data), 'black_wrap')

            # scroll to the end
            @buffer.move_mark('end_mark', @buffer.end_iter)
			
			# Handle cases where the window was closed
			begin
	            @view.scroll_mark_onscreen(@buffer.get_mark('end_mark'))
			rescue
			end
			
          end

          private

          #
          # Describe the auxiliary options
          #
          def append_review(aux, data)
            @r_buffer.delete(*@r_buffer.bounds)
            start = @r_buffer.get_iter_at_offset(0)

            # Module name
            @r_buffer.insert_with_tags(start, aux + "\n", 'forestgreen_bold_center')

            # Pair key => Value
            data.sort.each do |key, value|
              @r_buffer.insert_with_tags(start, "#{key}", 'rosybrown_bold')
              @r_buffer.insert_with_tags(start, " => #{value}\n", 'black_bold')
            end
          end

        end

      end

    end
  end
end
