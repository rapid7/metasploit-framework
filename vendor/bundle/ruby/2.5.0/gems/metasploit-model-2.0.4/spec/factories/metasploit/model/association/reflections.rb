FactoryGirl.define do
  sequence :metasploit_model_association_reflection_class_name do |n|
    "Metasploit::Model::Association::Reflection::Class#{n}"
  end

  sequence :metasploit_model_association_reflection_name do |n|
    "metasploit_model_association_reflection_name#{n}".to_sym
  end
end