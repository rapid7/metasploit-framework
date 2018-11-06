# Extracts the `Arel::Attribute` objects from `Metasploit::Model::Search::Operator::Base` subclasses.
class MetasploitDataModels::Search::Visitor::Attribute
  include Metasploit::Model::Visitation::Visit

  visit 'Metasploit::Model::Search::Operator::Association' do |operator|
    visit operator.source_operator
  end

  visit 'Metasploit::Model::Search::Operator::Attribute',
        'MetasploitDataModels::Search::Operator::IPAddress',
        'MetasploitDataModels::Search::Operator::Port::List' do |operator|
    table = operator.klass.arel_table
    table[operator.attribute]
  end

  Metasploit::Concern.run(self)
end
