FactoryBot.define do
  factory :mdm_module_arch, :class => Mdm::Module::Arch do
    name { generate :mdm_module_arch_name }

    #
    # Associations
    #
    association :detail, :factory => :mdm_module_detail
  end

  sequence :mdm_module_arch_name do |n|
    "Mdm::Module::Arch#name #{n}"
  end
end
