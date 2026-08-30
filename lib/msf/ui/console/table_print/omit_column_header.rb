# -*- coding: binary -*-

module Msf
  module Ui
    module Console
      module TablePrint
        class OmitColumnHeader
          def style(_column)
            ''
          end
        end
      end
    end
  end
end
