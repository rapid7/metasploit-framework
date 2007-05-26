module Msf
  module Ui
    module Gtk2

      class MsfTypes

        #
        # OptRaw     - Multi-byte raw string
        #
        class Raw < Msf::Ui::Gtk2::SkeletonType

          def initialize(key, opt)
            super()

            pack_description(opt.desc.to_s + " :")
            pack_raw(key, opt.default)

            return self
          end

          #
          #
          #
          def pack_raw(name, value)
            hbox = Gtk::HBox.new(false, 10)
            self.pack_start(hbox, false, false, 0)

            @name = name

            label = Gtk::Label.new
            label.set_markup("<span foreground=\"black\">#{@name} :</span>")
            hbox.pack_start(label, false, false, 0)

            @combo = Gtk::ComboBox.new(true)
            exitfunc = ["seh", "thread", "process"]
            exitfunc.each_with_index do |val, idx|
              @combo.prepend_text(val)
              if (val == value)
                @combo.set_active(idx)
              end
            end

            hbox.pack_start(@combo, false, false, 0)
          end

          #
          #
          #
          def check?
            return @combo.active
          end

          #
          #
          #
          def get_pair
            return @name, @combo.active_text
          end

        end

      end

    end

  end
end
