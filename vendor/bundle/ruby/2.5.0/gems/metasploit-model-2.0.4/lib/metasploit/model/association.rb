# Allows registering the class name of assocations similar to ActiveRecord associations, so that ActiveModel
# associations can be reflected with the same API as ActiveRecord associations.
module Metasploit::Model::Association
  extend ActiveSupport::Autoload
  extend ActiveSupport::Concern

  autoload :Error
  autoload :Reflection
  autoload :Tree

  # Defines DSL for define associations on ActiveModels with {#association}, which can then be retrieved in bulk
  # with {#association_by_name} or a single association's reflection by name with {#reflect_on_association}.
  module ClassMethods
    # Registers an association.
    #
    # @param name [to_sym] Name of the association
    # @param options [Hash{Symbol => String}]
    # @option options [String] :class_name Name of association's class.
    # @return [Metasploit::Model::Association::Reflection] the reflection of the registered association.
    # @raise [Metasploit::Model::Invalid] if name is blank.
    # @raise [Metasploit::Model::Invalid] if :class_name is blank.
    def association(name, options={})
      association = Metasploit::Model::Association::Reflection.new(
          :model => self,
          :name => name.to_sym,
          :class_name => options[:class_name]
      )
      association.valid!

      association_by_name[association.name] = association
    end

    # Associations registered with {#association}.
    #
    # @return [Hash{Symbol => Metasploit::Model::Association::Reflection}] Maps
    #   {Metasploit::Model::Association::Reflection#name} to {Metasploit::Model::Association::Reflection}.
    def association_by_name
      @association_by_name ||= {}
    end

    # Returns reflection for association with the given name.
    #
    # @param name [#to_sym] name of the association whose reflection to retrieve.
    # @return [nil] if no association with the given `name`.
    # @return [Metasploit::Model::Association::Reflection] if association with the given `name`.
    def reflect_on_association(name)
      association_by_name[name.to_sym]
    end
  end
end
