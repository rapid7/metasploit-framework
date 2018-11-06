module FactoryBot
  # @api private
  class AttributeAssigner
    def initialize(evaluator, build_class, &instance_builder)
      @build_class = build_class
      @instance_builder         = instance_builder
      @evaluator                = evaluator
      @attribute_list           = evaluator.class.attribute_list
      @attribute_names_assigned = []
    end

    def object
      @evaluator.instance = build_class_instance
      build_class_instance.tap do |instance|
        attributes_to_set_on_instance.each do |attribute|
          instance.public_send("#{attribute}=", get(attribute))
          @attribute_names_assigned << attribute
        end
      end
    end

    def hash
      @evaluator.instance = build_hash

      attributes_to_set_on_hash.inject({}) do |result, attribute|
        result[attribute] = get(attribute)
        result
      end
    end

    private

    def method_tracking_evaluator
      @method_tracking_evaluator ||= Decorator::AttributeHash.new(decorated_evaluator, attribute_names_to_assign)
    end

    def decorated_evaluator
      Decorator::InvocationTracker.new(
        Decorator::NewConstructor.new(@evaluator, @build_class)
      )
    end

    def methods_invoked_on_evaluator
      method_tracking_evaluator.__invoked_methods__
    end

    def build_class_instance
      @build_class_instance ||= method_tracking_evaluator.instance_exec(&@instance_builder)
    end

    def build_hash
      @build_hash ||= NullObject.new(hash_instance_methods_to_respond_to)
    end

    def get(attribute_name)
      @evaluator.send(attribute_name)
    end

    def attributes_to_set_on_instance
      (attribute_names_to_assign - @attribute_names_assigned - methods_invoked_on_evaluator).uniq
    end

    def attributes_to_set_on_hash
      attribute_names_to_assign - association_names
    end

    def attribute_names_to_assign
      @attribute_names_to_assign ||= non_ignored_attribute_names + override_names - ignored_attribute_names - alias_names_to_ignore
    end

    def non_ignored_attribute_names
      @attribute_list.non_ignored.names
    end

    def ignored_attribute_names
      @attribute_list.ignored.names
    end

    def association_names
      @attribute_list.associations.names
    end

    def override_names
      @evaluator.__override_names__
    end

    def hash_instance_methods_to_respond_to
      @attribute_list.names + override_names + @build_class.instance_methods
    end

    def alias_names_to_ignore
      @attribute_list.non_ignored.flat_map do |attribute|
        override_names.map { |override| attribute.name if attribute.alias_for?(override) && attribute.name != override && !ignored_attribute_names.include?(override) }
      end.compact
    end
  end
end
