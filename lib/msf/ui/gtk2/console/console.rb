module Msf
  module Ui
    module Gtk2

      class Console



        #
        # Classic console herited from Gtk::Window
        #
        class Shell < Msf::Ui::Gtk2::SkeletonConsole

          def initialize(iter)
            super(iter)
          end

        end # Shell

        #
        # Meterpreter Console
        #
        class Meterpreter < Msf::Ui::Gtk2::SkeletonConsole

          def inititialize(iter)
            print "TODO: On the meterpreter console place"
            super(iter)
            run_cmd("help")
          end

        end # Meterpreter
        
      end # Console

    end
  end
end
