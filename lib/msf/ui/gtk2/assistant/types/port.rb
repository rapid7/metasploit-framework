module Msf
  module Ui
    module Gtk2

      class MsfTypes

        #
        # OptRaw     - Multi-byte raw string
        #
        class Port < Msf::Ui::Gtk2::SkeletonType

          def initialize(key, opt)
            super()

            pack_description(opt.desc.to_s + " :")
            pack_port(key, opt.default)

            return self
          end

          #
          #
          #
          def pack_port(name, value)
            hbox = Gtk::HBox.new(false, 10)
            self.pack_start(hbox, false, false, 0)
            
            @name = name            

            label = Gtk::Label.new
            label.set_markup("<span foreground=\"black\">#{@name} :</span>")
            hbox.pack_start(label, false, false, 0)

            @entry = Gtk::Entry.new
            @entry.set_text(value.to_s)
            @entry.set_width_chars(5)
            @entry.set_max_length(5)
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
