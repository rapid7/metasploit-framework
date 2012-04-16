module Formtastic
  module Inputs
    module Base
      
      attr_accessor :builder, :template, :object, :object_name, :method, :options
      
      def initialize(builder, template, object, object_name, method, options)
        @builder = builder
        @template = template
        @object = object
        @object_name = object_name
        @method = method
        @options = options.dup
        
        removed_option!(:label_method)
        removed_option!(:value_method)
        removed_option!(:group_label_method)
      end
      
      # Usefull for deprecating options.
      def warn_and_correct_option!(old_option_name, new_option_name)
        if options.key?(old_option_name)
          ::ActiveSupport::Deprecation.warn("The :#{old_option_name} option is deprecated in favour of :#{new_option_name} and will be removed from Formtastic after 2.0")
          options[new_option_name] = options.delete(old_option_name)
        end
      end
      
      # Usefull for raising an error on previously supported option.
      def removed_option!(old_option_name)
        raise ArgumentError, ":#{old_option_name} is no longer available" if options.key?(old_option_name)
      end
      
      extend ActiveSupport::Autoload
      
      autoload :Associations
      autoload :Collections
      autoload :Choices
      autoload :Database
      autoload :Errors
      autoload :Fileish
      autoload :GroupedCollections
      autoload :Hints
      autoload :Html
      autoload :Labelling
      autoload :Naming
      autoload :Numeric
      autoload :Options
      autoload :Placeholder
      autoload :Stringish
      autoload :Timeish
      autoload :Validations
      autoload :Wrapping
      
      include Html
      include Options
      include Database
      include Errors
      include Hints
      include Naming
      include Validations
      include Fileish
      include Associations
      include Labelling
      include Wrapping
      
    end
  end
end
  