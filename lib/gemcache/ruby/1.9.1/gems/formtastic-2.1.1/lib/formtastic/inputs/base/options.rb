module Formtastic
  module Inputs
    module Base
      module Options
        
        def input_options
          options.except(*formtastic_options)
        end
        
        def formtastic_options
          [:priority_countries, :priority_zones, :member_label, :member_value, :collection, :required, :label, :as, :hint, :input_html, :label_html, :value_as_class, :find_options, :class]
        end
      
      end
    end
  end
end

