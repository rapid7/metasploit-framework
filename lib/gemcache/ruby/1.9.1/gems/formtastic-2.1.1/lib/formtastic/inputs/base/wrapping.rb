module Formtastic
  module Inputs
    module Base
      # @todo relies on `dom_id`, `required?`, `optional`, `errors?`, `association_primary_key` & `sanitized_method_name` methods from another module
      module Wrapping
        
        # Override this method if you want to change the display order (for example, rendering the
        # errors before the body of the input).
        def input_wrapping(&block)
          template.content_tag(:li, 
            [template.capture(&block), error_html, hint_html].join("\n").html_safe, 
            wrapper_html_options
          )
        end
        
        def wrapper_html_options
          opts = (options[:wrapper_html] || {}).dup
          opts[:class] =
            case opts[:class]
            when Array
              opts[:class].dup
            when nil
              []
            else
              [opts[:class].to_s]
            end
          opts[:class] << as
          opts[:class] << "input"
          opts[:class] << "error" if errors?
          opts[:class] << "optional" if optional?
          opts[:class] << "required" if required?
          opts[:class] << "autofocus" if autofocus?
          opts[:class] = opts[:class].join(' ')
          
          opts[:id] ||= wrapper_dom_id
        
          opts
        end
        
        def wrapper_dom_id
          @wrapper_dom_id ||= "#{dom_id.to_s.gsub((association_primary_key || method).to_s, sanitized_method_name.to_s)}_input"
        end
                
      end
    end
  end
end
