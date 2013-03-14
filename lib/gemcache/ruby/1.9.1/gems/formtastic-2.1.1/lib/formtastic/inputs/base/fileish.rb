module Formtastic
  module Inputs
    module Base
      module Fileish
      
        def file?
          @file ||= begin
            # TODO return true if self.is_a?(Formtastic::Inputs::FileInput::Woo)
            object && object.respond_to?(method) && builder.file_methods.any? { |m| object.send(method).respond_to?(m) }
          end
        end
      
      end
    end
  end
end



        



