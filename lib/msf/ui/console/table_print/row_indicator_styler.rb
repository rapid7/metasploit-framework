# -*- coding: binary -*-

module Msf
  module Ui
    module Console
      module TablePrint
        class RowIndicatorStyler
          def style(str)
            str.to_s == 'true' ? '=>' : '  '
          end
        end
      end
    end
  end
end
