FactoryBot.define do
  factory :mdm_module_action, :class => Mdm::Module::Action do
    name { generate :mdm_module_action_name }

    #
    # Associations
    #
    association :detail, :factory => :mdm_module_detail
  end

  sequence :mdm_module_action_name do |n|
    "Mdm::Module::Action#name #{n}"
  end
end
