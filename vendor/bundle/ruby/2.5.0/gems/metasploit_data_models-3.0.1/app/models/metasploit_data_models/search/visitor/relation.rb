# Generates a `ActiveRecord::Relation` from an `Metasploit::Model::Search::Query#tree`
class MetasploitDataModels::Search::Visitor::Relation < Metasploit::Model::Base
  #
  # CONSTANTS
  #

  # `ActiveRecord::Relation` methods that can compute their argument with a visitor under the
  # {MetasploitDataModels::Search::Visitor} namespace.
  RELATION_METHODS = [
      :joins,
      :includes,
      :where
  ]

  #
  # Attributes
  #

  # @!attribute [rw] query
  #   The query to visit.  Query supplies Class with #scope upon which to build `ActiveRecord::Relation`.
  #
  #   @return [Metasploit::Model::Search::Query]
  attr_accessor :query

  #
  # Validations
  #

  validate :valid_query

  validates :query,
            :presence => true

  #
  # Methods
  #

  # Visits {#query} tree to produce an `ActiveRecord::Relation` on the `Metasploit::Model::Search::Query#klass`.
  #
  # @return [ActiveRecord::Relation]
  def visit
    tree = query.tree

    # Enumerable#inject does not support 3 arity for Hashes so need to unpack pair
    visitor_by_relation_method.inject(query.klass.all) do |relation, pair|
      relation_method, visitor = pair
      visited = visitor.visit(tree)
      relation.send(relation_method, visited)
    end
  end

  # Map method on `ActiveRecord::Relation` to visitor that can visit `Metasploit::Model::Search::Query#tree` to
  # produce the arguments to the method on `ActiveRecord::Relation`.
  #
  # @return [Hash{Symbol => #visit}]
  def visitor_by_relation_method
    # Enumerable#each_with_object does not support 3 arity for Hashes so need to unpack pair
    @visitor_by_relation_method ||= self.class.visitor_class_by_relation_method.each_with_object({}) { |pair, visitor_by_relation_method|
      relation_method, visitor_class = pair
      visitor_by_relation_method[relation_method] = visitor_class.new
    }
  end

  # Maps method on `ActiveRecord::Relation` to the `Class` under {MetasploitDataModels::Search::Visitor} whose
  # `#visit` method can produce the arguments to the `ActiveRecord::Relation` method.
  #
  # @return [Hash{Symbol => Class}]
  def self.visitor_class_by_relation_method
    @relation_method_by_visitor_class ||= RELATION_METHODS.each_with_object({}) { |relation_method, relation_method_by_visitor_class|
      visitor_class_name = "#{parent.name}::#{relation_method.to_s.camelize}"
      visitor_class = visitor_class_name.constantize

      relation_method_by_visitor_class[relation_method] = visitor_class
    }
  end

  private

  # Validates that {#query} is valid.
  #
  # @return [void]
  def valid_query
    if query and !query.valid?
      errors.add(:query, :invalid)
    end
  end

  private

  Metasploit::Concern.run(self)
end
