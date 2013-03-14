module Formtastic
  module Inputs
    module Base
      module Labelling
        
        include Formtastic::LocalizedString
        
        def label_html
          render_label? ? builder.label(input_name, label_text, label_html_options) : "".html_safe
        end
        
        def label_html_options
          # opts = options_for_label(options) # TODO
          opts = {}
          opts[:for] ||= input_html_options[:id]
          opts[:class] = [opts[:class]]
          opts[:class] << 'label'
          
          opts
        end
        
        def label_text
          ((localized_label || humanized_method_name) + requirement_text).html_safe
        end
        
        # TODO: why does this need to be memoized in order to make the inputs_spec tests pass? 
        def requirement_text_or_proc
          @requirement_text_or_proc ||= required? ? builder.required_string : builder.optional_string
        end
        
        def requirement_text
          if requirement_text_or_proc.respond_to?(:call)
            requirement_text_or_proc.call
          else
            requirement_text_or_proc
          end
        end

        def label_from_options
          options[:label]
        end

        def localized_label
          localized_string(method, label_from_options || method, :label)
        end
        
        def render_label?
          return false if options[:label] == false
          true
        end
        
      end
    end
  end
end