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
        # OptAddress - IP address or hostname
        #
        ###
        class Address < Msf::Ui::Gtk2::SkeletonType

          def initialize(key, opt, store)
            super(key, opt, store)

            return self
          end

          #
          # Pack OptAddress into an Gtk::Entry
          #
          def pack_option(default, store)
            hbox = Gtk::HBox.new(false, 10)
            self.pack_start(hbox, false, false, 0)

            @entry = Gtk::Entry.new

            # With reverse type payload, prepend the local ip address
            # if store not equal "", dump the content into the Gtk::Entry
            # or filled it with the default value
            if (self.key == "LHOST")
              if store
                @entry.set_text(store)
              else
                @entry.set_text(Rex::Socket.source_address)
              end
            else
              if store
                @entry.set_text(store)
              else
                @entry.set_text(default)
              end
            end
            @entry.set_width_chars(75)
            @entry.set_max_length(128)
            hbox.pack_start(@entry, false, false, 0)
          end

          #
          # Check if an IP address filled the entry ...  or not !
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

        end # MsfTypes::Address

      end # MsfTypes

    end
  end
end