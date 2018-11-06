# Allows `MetasploitDataModels::Search::Visitor::Where` to visit {Metasploit::Credential::Search::Operation::Type} so
# that the operation can be transformed into a an equality query.
module MetasploitDataModels::Search::Visitor::Where::MetasploitCredential
  extend ActiveSupport::Concern

  included do
    visit 'Metasploit::Credential::Search::Operation::Type' do |operation|
      attribute = attribute_visitor.visit operation.operator

      attribute.eq(operation.value)
    end
  end
end