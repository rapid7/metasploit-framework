# -*- coding: binary -*-

module Msf
  module Ui
    module Console
      module CommandDispatcher
        ###
        #
        # Generic file system commands
        #
        ###
        class LocalFileSystem
          include Rex::Ui::Text::DispatcherShell::CommandDispatcher
          include Msf::Ui::Console::LocalFileSystem

          #
          # List of supported commands.
          #
          # @return [Hash]
          def commands
            local_fs_commands
          end

          # @param [String]
          def name
            'Local File System'
          end

          def unknown_command(cmd, line)
            status = super

            status
          end
        end
      end
    end
  end
end
