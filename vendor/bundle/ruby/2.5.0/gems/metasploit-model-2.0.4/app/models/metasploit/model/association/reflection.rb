# Reflection of the call to {Metasploit::Model::Association::ClassMethods#association}.
class Metasploit::Model::Association::Reflection < Metasploit::Model::Base
  #
  # Attributes
  #

  # @!attribute [rw] class_name
  #   The name {#klass}.  The name of {#klass} is given instead of {#klass} directly when initializing this
  #   reflection to prevent circular references with autoloading or ActiveSupport::Dependencies loading.
  #
  #   @return [String] Fully-qualified name of class in this association
  attr_accessor :class_name

  # @!attribute [rw] model
  #   The model on which this association was declared.  The equivalent for ActiveRecord association reflections
  #   would be #active_record.
  #
  #   @return [Class]
  attr_accessor :model

  # @!attribute [rw] name
  #   The name of this association.
  #
  #   @return [String]
  attr_accessor :name

  #
  # Validations
  #

  validates :model, :presence => true
  validates :name, :presence => true
  validates :class_name, :presence => true

  #
  # Methods
  #

  # Class with name {#class_name}.
  #
  # @return []
  # @raise [NameError] if {#class_name} cannot be constantized
  def klass
    class_name.constantize
  end
end
