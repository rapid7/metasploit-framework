class QueryMeta
  attr_accessor :filter_on
  attr_accessor :associated_attributes

  def initialize
    @filter_on = []
    @associated_attributes = []
  end

  def add_filter_item(item)
    @filter_on << item
  end

  def add_associated_attribute(query_meta)
    @associated_attributes << query_meta
  end

end