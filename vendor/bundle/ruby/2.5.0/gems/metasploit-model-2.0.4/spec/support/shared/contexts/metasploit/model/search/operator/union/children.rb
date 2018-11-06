RSpec.shared_context 'Metasploit::Model::Search::Operator::Group::Union#children' do
  subject(:children) do
    operator.children(formatted_value)
  end

  def child(formatted_operator)
    operator_name = formatted_operator.to_sym

    children.find { |operation|
      operation.operator.name == operator_name
    }
  end
end