module Formtastic
  module Inputs
    module Base
      module Placeholder
        
        def input_html_options
          {:placeholder => placeholder_text}.merge(super)
        end
        
        def placeholder_text
          localized_string(method, options[:placeholder], :placeholder)
        end
        
      end
    end
  end
end