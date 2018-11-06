# Gathers all the association names to pass to `ActiveRecord::Relation#joins` from a `Metasploit::Model::Search::Query`
class MetasploitDataModels::Search::Visitor::Joins
  include Metasploit::Model::Visitation::Visit

  #
  # Visitors
  #

  visit 'Metasploit::Model::Search::Group::Intersection',
        'Metasploit::Model::Search::Operation::Group::Intersection' do |parent|
    parent.children.flat_map { |child|
      visit child
    }
  end

  visit 'Metasploit::Model::Search::Group::Union',
        'Metasploit::Model::Search::Operation::Group::Union' do |parent|
    # A Set<Set> because if all children have multiple joins, but those multiple joins contain the same elements for
    # all children, then all joins can be counted as common:
    #
    #  (a.b:1 && c.d:2) || (a.b:3 && c.d:4) should return [:a, :c] since its common to both
    #  (a.b:1 && c.d:2 && e.f:3) || (a.b:3 && c.d:4) should return [:a, :c] since its the common _subset_
    join_set_set = parent.children.each_with_object(Set.new) { |child, set|
      child_joins = visit child
      child_join_set = Set.new child_joins

      set.add child_join_set
    }

    common_join_set = join_set_set.reduce { |common_subset, set|
      common_subset & set
    }

    common_join_set.to_a
  end

  visit 'Metasploit::Model::Search::Operation::Association' do |operation|
    association = visit operation.operator
    nested_associations = visit operation.source_operation

    if nested_associations.empty?
      [association]
    else
      [
          {
              association => nested_associations
          }
      ]
    end
  end

  visit 'Metasploit::Model::Search::Operation::Base' do |operation|
    visit operation.operator
  end

  visit 'Metasploit::Model::Search::Operator::Association' do |operator|
    operator.association
  end

  visit 'Metasploit::Model::Search::Operator::Attribute',
        'MetasploitDataModels::Search::Operator::IPAddress',
        'MetasploitDataModels::Search::Operator::Port::List' do |_|
    []
  end

  Metasploit::Concern.run(self)
end