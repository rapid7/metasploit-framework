module Formtastic
  module Inputs
    module Base
      module Database
        
        def column
          object.column_for_attribute(method) if object.respond_to?(:column_for_attribute)
        end
        
        def column?
          !column.nil?
        end
        
      end
    end
  end
end