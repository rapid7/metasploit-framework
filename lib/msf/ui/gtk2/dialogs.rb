module Msf
  module Ui
    module Gtk2

      class SkeletonAlert < Gtk::Dialog
        def initialize(parent, title, stock_icon, buttons, message=nil)
          super("", parent, Gtk::Dialog::DESTROY_WITH_PARENT, *buttons)

          self.border_width = 6
          self.resizable = false
          self.has_separator = false
          self.vbox.spacing = 12

          hbox = Gtk::HBox.new(false, 12)
          hbox.border_width = 6
          self.vbox.pack_start(hbox)

          image = Gtk::Image.new(stock_icon,
          Gtk::IconSize::DIALOG)
          image.set_alignment(0.5, 0)
          hbox.pack_start(image)

          vbox = Gtk::VBox.new(false, 6)
          hbox.pack_start(vbox)

          label = Gtk::Label.new
          label.set_alignment(0, 0)
          label.wrap = true
          label.markup = "<b><big>#{title}</big></b>"
          vbox.pack_start(label)

          if message
            label = Gtk::Label.new
            label.markup = message.strip
            label.set_alignment(0, 0)
            label.wrap = true
            vbox.pack_start(label)
          end
        end
      end

      class SkeletonView < Gtk::Dialog
        def initialize(title, buffer)
          super(title, $gtk2driver.main, Gtk::Dialog::Flags::MODAL,
          [ Gtk::Stock::CLOSE, Gtk::Dialog::RESPONSE_NONE ])

          self.border_width = 10
          self.vbox.spacing = 10
          self.set_default_size(400, 350)

          view = Gtk::TextView.new(buffer)
          scrolled_window = Gtk::ScrolledWindow.new
          scrolled_window.add(view)
          self.vbox.pack_start(scrolled_window, true, true, 5)
          scrolled_window.set_policy(Gtk::POLICY_AUTOMATIC, Gtk::POLICY_AUTOMATIC)
        end
      end

      ##
      # Class and subclass for all MsfDialog
      ##
      class MsfDialog

        ##
        # Class for the payload rendering
        # title: the payload refname
        # payload: the generated payload
        ##
        class Payload < Msf::Ui::Gtk2::SkeletonView
          def initialize(title, payload)
            @buffer = Gtk::TextBuffer.new
            super(title, @buffer)

            colorize()
            display(payload)

            self.default_response = Gtk::Dialog::RESPONSE_NONE
            show_all and run
            destroy
          end

          #
          # Display the generated payload with color
          #
          def display(payload)
            filter = /^\#/
            @buffer.delete(*@buffer.bounds)
            start = @buffer.get_iter_at_offset(0)

            payload.each do |line|
              if ( line.match(filter) )
                @buffer.insert_with_tags(start, line, 'comments')
              else
                @buffer.insert_with_tags(start, line, '_')
              end
            end
          end

          #
          # Create tags for the syntax color
          #
          def colorize
            @buffer.create_tag("comments",
            :'foreground' => 'RosyBrown',
            :'weight' => Pango::FontDescription::WEIGHT_BOLD
            )

            @buffer.create_tag("_",
            :'weight' => Pango::FontDescription::WEIGHT_BOLD
            )
          end
        end

        ##
        # Display an error Gtk style
        # parent: the Gtk parent widget
        # title: the error title
        # message: the error
        ##
        class Error < Msf::Ui::Gtk2::SkeletonAlert
          def initialize(parent, title, message=nil)
            super(parent, title, Gtk::Stock::DIALOG_ERROR,
            [[Gtk::Stock::OK, Gtk::Dialog::RESPONSE_OK]],
            message)
            self.default_response = Gtk::Dialog::RESPONSE_OK
            show_all and run
            destroy
          end
        end
      end

    end
  end
end
