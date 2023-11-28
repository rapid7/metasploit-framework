# -*- coding: binary -*-

module Msf
  module Ui
    module Console
      module TablePrint
        class BlankFormatter
          def format(value)
            return '.' if value.blank?

            value
          end
        end
      end
    end
  end
end
