FactoryBot.define do
  factory :mdm_module_author, :class => Mdm::Module::Author do
    name { generate :mdm_module_author_name }

    #
    # Associations
    #
    association :detail, :factory => :mdm_module_detail

    factory :full_mdm_module_author do
      email { generate :mdm_module_author_name }
    end
  end

  sequence :mdm_module_author_name do |n|
    "Mdm::Module::Author#name #{n}"
  end

  sequence :mdm_module_author_email do |n|
    "Mdm::Module::Author#email #{n}"
  end
end
