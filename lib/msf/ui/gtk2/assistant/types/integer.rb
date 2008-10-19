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
        # OptInt     - An integer value
        #
        ###
        class Int < Msf::Ui::Gtk2::SkeletonType

          include Msf::Ui::Gtk2::MyControls

          def initialize(key, opt, store)
            super(key, opt, store)

            return self
          end

          #
          # Pack OptInt into an Gtk::Entry
          #
          def pack_option(default, store)
            hbox = Gtk::HBox.new(false, 10)
            self.pack_start(hbox, false, false, 0)

            @entry = Gtk::Entry.new
            @entry.set_width_chars(15)
            @entry.set_max_length(15)

            if store
              @entry.set_text(store.to_s)
            else
              @entry.set_text(default.to_s)
            end
            
            hbox.pack_start(@entry, false, false, 0)
          end

          #
          # Check if the entry is empty ...  or not !
          #
          def check?
            if (@entry.text == "")
              false
            else
              true
            end
          end

          #
          # Return key/value pair
          #
          def get_pair
            return self.key, @entry.text
          end

        end # MSfTypes::Integer

      end # MsfTypes

    end
  end
end