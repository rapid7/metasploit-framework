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
          def initialize(iter)

            # meterpreter client
            client = iter[3]

            # call the parent
            super(iter)
            
            # Not sexy
            # TODO: use the API
            send_cmd("execute -f cmd.exe -i -H")            

          end

        end # Meterpreter

      end # Console

    end
  end
end
