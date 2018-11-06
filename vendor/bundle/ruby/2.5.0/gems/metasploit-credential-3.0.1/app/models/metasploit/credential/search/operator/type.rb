# Operator that searches a polymorphic `#type` attribute.  Search terms are restricted to set of `Class#name`s and
# `Class#model_name.human` with the `Class#model_name.human` being translated to `Class#name` in the operation returned
# by `#operate_on`.
class Metasploit::Credential::Search::Operator::Type < Metasploit::Model::Search::Operator::Attribute
  #
  # Attributes
  #

  # @!attribute class_names
  #   The name of the classes that are allowed for {#attribute}.  `Class.name`s must be supplied as there's no way in
  #   Rails to reflectively determine all allowed values for a polymorphic type.
  #
  #   @return [Array<String>]
  attr_writer :class_names

  #
  # Validations
  #

  validates :class_names,
            presence: true

  #
  # Instance Methods
  #

  # Defaults to `:type` as all STI tables in `ActiveRecord::Base` use `type` as teh type attribute by default.  Override
  # to search foreign key types, which are prefixed with the association name.
  #
  # @return [Symbol]
  def attribute
    @attribute ||= :type
  end

  # The name of the classes that are allowed for {#attribute}.  `Class.name`s must be supplied as there's no way in
  # Rails to reflectively determine all allowed values for a polymorphic type.
  #
  # @return [Array<String>]
  def class_names
    @class_names ||= []
  end

  # Maps `Class.model_name.human` to `Class.name` for {#class_set}.
  #
  # @return [Hash{String => String}] Maps `Class.model_name.name`s to `Class.name`s so `Class.model_names.name` can be
  #   converted to `Class.name` for the in database search.
  def class_name_by_class_model_name_human
    @class_name_by_class_model_name_human ||= class_set.each_with_object({}) { |klass, class_name_by_class_model_name_human|
      class_name_by_class_model_name_human[klass.model_name.human] = klass.name
    }
  end

  # Set of `Class`es whose `Class#name` or `Class.model_name.name`
  #
  # @return [Set<Class>]
  def class_set
    @class_set ||= class_names.each_with_object(Set.new) { |class_name, set|
      set.add class_name.constantize
    }
  end

  # @return [String] 'Metasploit::Credential::Search::Operation::Type'
  def operation_class_name
    'Metasploit::Credential::Search::Operation::Type'
  end

  # The type attribute for STI and polymorphic associations is a string on the database.
  #
  # @return [String] `:string`
  def type
    :string
  end
end