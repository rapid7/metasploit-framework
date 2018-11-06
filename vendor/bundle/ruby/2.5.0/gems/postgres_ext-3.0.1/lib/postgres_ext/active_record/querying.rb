module ActiveRecord::Querying
  delegate :with, :ranked, to: :all

  def from_cte(name, expression)
    table = Arel::Table.new(name)

    cte_proxy = CTEProxy.new(name, self)
    relation = ActiveRecord::Relation.new cte_proxy, cte_proxy.arel_table
    relation.with name => expression
  end
end
