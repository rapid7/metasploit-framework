module Formtastic
  module Inputs
    module Base
      module Numeric
        def input_html_options
          defaults = super

          # override rails default size - not valid on numeric inputs
          #@todo document/spec
          defaults[:size] = nil
          
          if in_option
            defaults[:min] = in_option.to_a.min
            defaults[:max] = in_option.to_a.max
          else
            defaults[:min]  ||= min_option
            defaults[:max]  ||= max_option
          end
          defaults[:step] ||= step_option
          defaults
        end
        
        def step_option
          return options[:step] if options.key?(:step)
          validation_step
        end
        
        def min_option
          return options[:min] if options.key?(:min)
          validation_min
        end
        
        def max_option
          return options[:max] if options.key?(:max)
          validation_max
        end
        
        def in_option
          options[:in]
        end
        
        def wrapper_html_options
          new_class = [super[:class], "numeric", "stringish"].compact.join(" ")
          super.merge(:class => new_class)
        end
        
      end
    end
  end
end