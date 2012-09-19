module Formtastic
  module Inputs
    module Base
      module Naming

        def as
          self.class.name.split("::").last.underscore.gsub(/_input$/, '')
        end
        
        def sanitized_object_name
          object_name.to_s.gsub(/\]\[|[^-a-zA-Z0-9:.]/, "_").sub(/_$/, "")
        end

        def sanitized_method_name
          @sanitized_method_name ||= method.to_s.gsub(/[\?\/\-]$/, '')
        end

        def attributized_method_name
          method.to_s.gsub(/_id$/, '').to_sym
        end
        
        def humanized_method_name
          if builder.label_str_method != :humanize
            # Special case where label_str_method should trump the human_attribute_name
            # TODO: is this actually a desired bheavior, or should we ditch label_str_method and
            # rely purely on :human_attribute_name.
            method.to_s.send(builder.label_str_method)
          elsif object && object.class.respond_to?(:human_attribute_name)
            object.class.human_attribute_name(method.to_s)
          else
            method.to_s.send(builder.label_str_method)
          end
        end

        def input_name
          association_primary_key
        end

      end
    end
  end
end