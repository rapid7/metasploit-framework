# Gathers all the association names to pass to `ActiveRecord::Relation#includes` from a
# `Metasploit::Model::Search::Query`
class MetasploitDataModels::Search::Visitor::Includes
  include Metasploit::Model::Visitation::Visit

  #
  # Visitors
  #

  visit 'Metasploit::Model::Search::Group::Base',
        'Metasploit::Model::Search::Operation::Group::Base' do |parent|
    parent.children.flat_map { |child|
      visit child
    }
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
        'MetasploitDataModels::Search::Operator::Port::List' do |_operator|
    []
  end

  Metasploit::Concern.run(self)
end
