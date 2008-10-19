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
        # OptPath    - Path name on disk
        #
        ###
        class Path < Msf::Ui::Gtk2::SkeletonType
          
          def initialize(key, opt, store)
            super(key, opt, store)

            return self
          end

          #
          # FileChooser for OptPath
          #
          def pack_option(default, store)
            hbox = Gtk::HBox.new(false, 10)
            self.pack_start(hbox, false, false, 0)
            @button = Gtk::FileChooserButton.new("Select a file", Gtk::FileChooser::ACTION_OPEN)
            @button.set_width_chars(15)
            
            if store
              @button.set_filename(File.expand_path(store.to_s))
            else
              if File.exist?(default)
                @button.set_filename(default)
              end
            end
            
            hbox.pack_start(@button, false, false, 0)
          end

          #
          # Check if the entry is empty ...  or not !
          #
          def check?
            if (@button.filename == nil)
              false
            else
              true
            end
          end

          #
          # Return the the pair key/value
          #
          def get_pair
            return self.key, @button.filename
          end

        end # MsfTypes::Path

      end # MsfTypes

    end
  end
end