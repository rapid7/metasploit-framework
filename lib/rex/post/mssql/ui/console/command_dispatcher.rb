# -*- coding: binary -*-

require 'rex/ui/text/dispatcher_shell'
require 'rex/post/sql/ui/console/command_dispatcher'

module Rex
  module Post
    module MSSQL
      module Ui
        ###
        #
        # Base class for all command dispatchers within the MSSQL console user interface.
        #
        ###
        module Console::CommandDispatcher
          include Rex::Post::Sql::Ui::Console::CommandDispatcher

          #
          # Return the subdir of the `documentation/` directory that should be used
          # to find usage documentation
          #
          # @return [String]
          def docs_dir
            ::File.join(super, 'mssql_session')
          end
        end
      end
    end
  end
end
