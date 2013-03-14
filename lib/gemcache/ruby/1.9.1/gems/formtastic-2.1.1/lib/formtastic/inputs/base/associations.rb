module Formtastic
  module Inputs
    module Base
      module Associations
        include Formtastic::Helpers::Reflection

        # :belongs_to, etc
        def association
          @association ||= association_macro_for_method(method)
        end

        def reflection
          @reflection ||= reflection_for(method)
        end

        def belongs_to?
          association == :belongs_to
        end

        def has_many?
          association == :has_many
        end

        def association_primary_key
          association_primary_key_for_method(method)
        end

      end
    end
  end
end
