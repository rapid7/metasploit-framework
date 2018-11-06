class CTEProxy
  include ActiveRecord::Querying
  include ActiveRecord::Sanitization::ClassMethods
  include ActiveRecord::Reflection::ClassMethods

  attr_accessor :reflections, :current_scope
  attr_reader :connection, :arel_table

  def initialize(name, model)
    @name = name
    @arel_table = Arel::Table.new(name)
    @model = model
    @connection = model.connection
    @_reflections = {}
  end

  def name
    @name
  end

  def table_name
    name
  end

  delegate :column_names, :columns_hash, :model_name, :primary_key, :attribute_alias?,
    :aggregate_reflections, :instantiate, :type_for_attribute, :relation_delegate_class, to: :@model

  private

  def reflections
    @_reflections
  end

  alias _reflections reflections
end
