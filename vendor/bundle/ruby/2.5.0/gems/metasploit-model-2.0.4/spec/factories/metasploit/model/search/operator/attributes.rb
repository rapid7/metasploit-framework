FactoryGirl.define do
  sequence :metasploit_model_search_operator_attribute_attribute do |n|
    "metasploit_model_search_operator_attribute_attribute#{n}".to_sym
  end

  sequence :metasploit_model_search_operator_attribute_type, Metasploit::Model::Search::Operator::Attribute::TYPES.cycle
end