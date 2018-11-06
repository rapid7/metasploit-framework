FactoryBot.define do
  factory :mdm_module_platform, :class => Mdm::Module::Platform do
    name { generate :mdm_module_platform_name }

    #
    # Associations
    #
    association :detail, :factory => :mdm_module_detail
  end

  sequence :mdm_module_platform_name do |n|
    "Mdm::Module::Platform#name #{n}"
  end
end
