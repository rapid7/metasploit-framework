module Msf
  module Ui
    module Gtk2

      class MsfTypes

        #
        # OptRaw     - Multi-byte raw string
        #
        class Address < Msf::Ui::Gtk2::SkeletonType

          def initialize(key, opt, store)
            super()

            pack_description(opt.desc.to_s + " :")
            pack_address(key, opt.default, store)

            return self
          end

          #
          #
          #
          def pack_address(name, value, store)
            hbox = Gtk::HBox.new(false, 10)
            self.pack_start(hbox, false, false, 0)

            @name = name

            label = Gtk::Label.new
            label.set_markup("<span foreground=\"black\">#{@name} :</span>")
            hbox.pack_start(label, false, false, 0)

            @entry = Gtk::Entry.new
            if (name == "LHOST" and store == "")
              @entry.set_text(Rex::Socket.source_address)
            elsif (not store == "")
              @entry.set_text(store)
            else
              @entry.set_text(value)
            end
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
