FactoryBot.define do
  factory :mdm_module_ref, :class => Mdm::Module::Ref do
    name { generate :mdm_module_ref_name }

    #
    # Associations
    #
    association :detail, :factory => :mdm_module_detail
  end

  sequence :mdm_module_ref_name do |n|
    "Mdm::Module::Ref#name #{n}"
  end
end
