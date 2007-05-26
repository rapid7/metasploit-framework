module Msf
  module Ui
    module Gtk2

      class MsfTypes

        #
        # OptBool    - Boolean true or false indication
        #
        class Bool < Msf::Ui::Gtk2::SkeletonType

          def initialize(key, opt)
            super()

            pack_description(opt.desc.to_s + " :")
            pack_bool(key, opt.default)

            return self
          end

          #
          #
          #
          def pack_bool(name, value)
            hbox = Gtk::HBox.new(false, 0)
            self.pack_start(hbox, false, false, 0)
            
            @name = name

            @checkbutton = Gtk::CheckButton.new(@name, true)
            hbox.pack_start(@checkbutton, true, true, 0)

            @checkbutton.set_active(value)
          end

          #
          #
          #
          def check?
            return @checkbutton.active?
          end

          #
          #
          #
          def get_pair
            return @name, @checkbutton.active?
          end

        end

      end

    end

  end
end
