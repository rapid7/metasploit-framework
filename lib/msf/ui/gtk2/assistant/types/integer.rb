module Msf
  module Ui
    module Gtk2

      class MsfTypes

        #
        # OptString  - Multi-byte character string
        #
        class Integer < Msf::Ui::Gtk2::SkeletonType

          include Msf::Ui::Gtk2::MyControls

          def initialize(key, opt)
            super()

            pack_description(opt.desc.to_s + " :")
            pack_integer(key, opt.default.to_s)

            return self
          end

          #
          #
          #
          def pack_integer(name, value)
            hbox = Gtk::HBox.new(false, 10)
            self.pack_start(hbox, false, false, 0)
            
            @name = name

            label = Gtk::Label.new
            label.set_markup("<span foreground=\"black\">#{@name} :</span>")
            hbox.pack_start(label, false, false, 0)

            @entry = Gtk::Entry.new
            @entry.set_text(value.to_s)
            @entry.set_width_chars(15)
            @entry.set_max_length(15)
            hbox.pack_start(@entry, false, false, 0)
          end

          #
          #
          #
          def check?
            if (@entry.text == "")
              false
            else
              true
            end
          end

          #
          #
          #
          def get_pair
            return @name, @entry.text
          end

        end

      end

    end

  end
end
