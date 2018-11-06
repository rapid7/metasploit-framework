FactoryGirl.define do
  sequence :metasploit_model_search_operator_base_name do |n|
    "metasploit_model_search_operator_base_name#{n}".to_sym
  end
end