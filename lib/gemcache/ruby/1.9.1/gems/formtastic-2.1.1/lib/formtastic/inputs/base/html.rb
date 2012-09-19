module Formtastic
  module Inputs
    module Base
      module Html
        
        # Defines how the instance of an input should be rendered to a HTML string.
        #
        # @abstract Implement this method in your input class to describe how the input should render itself.
        #
        # @example A basic label and text field input inside a standard wrapping might look like this:
        #     def to_html
        #       input_wrapping do
        #         label_html <<
        #         builder.text_field(method, input_html_options)
        #       end
        #     end
        def to_html
          raise NotImplementedError
        end
        
        def input_html_options
          { 
            :id => dom_id,
            :required => required_attribute?,
            :autofocus => autofocus?
          }.merge(options[:input_html] || {})
        end
        
        def dom_id
          [
            builder.custom_namespace, 
            sanitized_object_name, 
            dom_index, 
            association_primary_key || sanitized_method_name
          ].reject { |x| x.blank? }.join('_')
        end
        
        def dom_index
          if builder.options.has_key?(:index)
            builder.options[:index]
          elsif !builder.auto_index.blank?
            # TODO there's no coverage for this case, not sure how to create a scenario for it
            builder.auto_index
          else
            ""
          end
        end

      end
    end
  end
end
