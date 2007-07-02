module Msf
  module Ui
    module Gtk2

      class Console

        ###
        #
        # Classic console herited from SkeletonConsole
        #
        ###
        class Shell < Msf::Ui::Gtk2::SkeletonConsole
          
          def initialize(iter)
            client = iter[3]
            super(iter)
            
            if (client.type == "meterpreter")
              
              # TODO: use the API instead writing into the pipe
              send_cmd("execute -f cmd.exe -i -H")
            end              
          end

        end # Console::Shell

        ###
        #
        # Meterpreter Console herited from SkeletonConsole
        #
        ###
        class Meterpreter < Msf::Ui::Gtk2::SkeletonConsole
          
          def initialize(iter)
            # meterpreter client
            client = iter[3]

            # call the parent
            super(iter)
            
            # TODO: use the API instead writing into the pipe
            send_cmd("help")
          end

        end # Console::Meterpreter

      end # Console

    end
  end
end
