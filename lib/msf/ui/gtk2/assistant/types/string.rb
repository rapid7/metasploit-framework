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
        # OptString  - Multi-byte character string
        #
        ###
        class String < Msf::Ui::Gtk2::SkeletonType

          def initialize(key, opt, store)
            super(key, opt, store)
            
            return self
          end

          #
          # Pack OptString into an Gtk::Entry
          #
          def pack_option(default, store)
            hbox = Gtk::HBox.new(false, 10)
            self.pack_start(hbox, false, false, 0)

            @entry = Gtk::Entry.new
            if store
              @entry.set_text(store)
            else
              @entry.set_text(default)
            end
            
            if (self.key == "Locale")
              @entry.set_width_chars(15)
              @entry.set_max_length(15)
              hbox.pack_start(@entry, false, false, 0)
            else
              hbox.pack_start(@entry, true, true, 0)
            end
          end

          #
          # Check if the option is empty ...  or not !
          #
          def check?
            if (@entry.text == "")
              false
            else
              true
            end
          end

          #
          # Return the the pair key/value
          #
          def get_pair
            return self.key, @entry.text
          end

        end

      end

    end
  end
end