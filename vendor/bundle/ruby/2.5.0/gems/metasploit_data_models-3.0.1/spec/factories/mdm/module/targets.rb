FactoryBot.define do
  factory :mdm_module_target, :class => Mdm::Module::Target do
    index { generate :mdm_module_target_index }
    name { generate :mdm_module_target_name }

    #
    # Associations
    #
    association :detail, :factory => :mdm_module_detail
  end

  sequence :mdm_module_target_index do |n|
    n
  end

  sequence :mdm_module_target_name do |n|
    "Mdm::Module::Target#name #{n}"
  end
end
