module Formtastic
  module Inputs
    module Base
      module Hints
        
        def hint_html
          if hint?
            template.content_tag(
              :p, 
              Formtastic::Util.html_safe(hint_text), 
              :class => (options[:hint_class] || builder.default_hint_class)
            )
          end
        end
        
        def hint?
          !hint_text.blank? && !hint_text.kind_of?(Hash)
        end

        def hint_text
          localized_string(method, options[:hint], :hint)
        end
        
        def hint_text_from_options
          options[:hint]
        end

      end
    end
  end
end
