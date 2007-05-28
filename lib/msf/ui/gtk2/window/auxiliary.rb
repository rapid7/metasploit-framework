module Msf
  module Ui
    module Gtk2

      class MsfWindow

        #
        #
        #
        class Auxiliary < Msf::Ui::Gtk2::SkeletonBasic

          include Msf::Ui::Gtk2::MyControls

          def initialize(title)
            console_style = File.join(driver.resource_directory, 'style', 'console.rc')
            Gtk::RC.parse(console_style)
            
            # call the parent
            super(title)

            @buffer = Gtk::TextBuffer.new

            # Define the size and border
            set_default_size(400, 400)
            set_border_width(10)

            # Main hbox
            vbox = Gtk::VBox.new(false, 0)
            add(vbox)

            @view = Gtk::TextView.new(@buffer)

            sw = Gtk::ScrolledWindow.new()
            sw.set_policy(Gtk::POLICY_AUTOMATIC, Gtk::POLICY_AUTOMATIC)
            vbox.pack_start(sw, true, true, 0)

            sw.add(@view)
            
            @buffer.create_tag("date",
            :'foreground' => 'ForestGreen',
            :'weight' => Pango::FontDescription::WEIGHT_BOLD
            )

            @buffer.create_tag("txt",
            :'foreground' => 'white'
            #:'weight' => Pango::FontDescription::WEIGHT_BOLD
            )

            return self
          end

          #
          # Adds text to the main logging screen
          #
          def append_log_view(data)
            
            if (not @buffer.get_mark('end_mark'))
              @buffer.create_mark('end_mark', @buffer.end_iter, false)
            end

            #@buffer.insert(@buffer.end_iter, Rex::Text.to_utf8(data))
            @buffer.insert_with_tags(@buffer.end_iter, Time.now.strftime("%H:%m:%S "), 'date')
            #@buffer.insert_with_tags(@buffer.end_iter, type, 'type')
            @buffer.insert_with_tags(@buffer.end_iter, data, 'txt')
            @buffer.move_mark('end_mark', @buffer.end_iter)
            @view.scroll_mark_onscreen(@buffer.get_mark('end_mark'))
          end

        end

      end

    end
  end
end
