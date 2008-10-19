module Msf
  module Ui
    module Gtk2
      
      ###
      #
      # This class is dedicated to support all MSF options by a Gtk2 widget
      #
      ###
      class MsfTypes

        ###
        #
        # OptBool    - Boolean true or false indication
        #
        ###
        class Bool < Msf::Ui::Gtk2::SkeletonType

          def initialize(key, opt, store)
            super(key, opt, store)

            return self
          end

          #
          # Pack OptBool into a Gtk::CheckButton
          #
          def pack_option(default, store)
            hbox = Gtk::HBox.new(false, 0)
            self.pack_start(hbox, false, false, 0)

            @checkbutton = Gtk::CheckButton.new(self.key.gsub("_", "__"))
            hbox.pack_start(@checkbutton, true, true, 0)

            # Define the CheckButton state
            if store
              if (store.to_s.downcase == "false")
                @checkbutton.set_active(false)
              else
                @checkbutton.set_active(true)
              end
            elsif
              if (default.to_s.downcase == "false")
                @checkbutton.set_active(false)
              else
                @checkbutton.set_active(true)
              end
            end
          end

          #
          # Check if the button is activate ...  or not !
          #
          def check?
            return @checkbutton.active?
          end

          #
          # Return key/value pair
          #
          def get_pair
            return self.key, @checkbutton.active?
          end

        end # MsfTypes::Bool

      end # MSfTypes

    end
  end
end