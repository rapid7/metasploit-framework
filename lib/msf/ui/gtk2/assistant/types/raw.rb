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
        # OptRaw     - Multi-byte raw string
        #
        ###
        class Raw < Msf::Ui::Gtk2::SkeletonType

          def initialize(key, opt, store)
            super(key, opt, store)

            return self
          end

          #
          # Pack a ComboBox to choose between seh, raw and process
          #
          def pack_option(default, store)
            lock_by_store = nil
            lock_by_default = nil
                        
            hbox = Gtk::HBox.new(false, 10)
            self.pack_start(hbox, false, false, 0)

            @combo = Gtk::ComboBox.new(true)
            exitfunc = ["seh", "thread", "process"]
            exitfunc.each_with_index do |val, idx|
              @combo.prepend_text(val)
              if (val == store)
                lock_by_store = idx
              elsif (val == default)
                lock_by_default = idx
              end
            end
            
            if lock_by_store
              @combo.set_active(lock_by_store)
            else
              @combo.set_active(lock_by_default)
            end

            hbox.pack_start(@combo, false, false, 0)
          end

          #
          # Check if an option is activate
          #
          def check?
            return @combo.active
          end

          #
          # Return the the pair key/value
          #
          def get_pair
            return self.key, @combo.active_text
          end

        end

      end

    end
  end
end