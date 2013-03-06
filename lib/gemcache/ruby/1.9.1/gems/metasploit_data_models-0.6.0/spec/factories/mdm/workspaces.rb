FactoryGirl.define do
  factory :mdm_workspace, :class => Mdm::Workspace do
    #
    # Associations
    #
    association :owner, :factory => :mdm_user

    #
    # Attributes
    #
    boundary { generate :mdm_ipv4_address }
    description { generate :mdm_workspace_description }
    name { generate :mdm_workspace_name }
  end

  sequence :mdm_workspace_description do |n|
    "Mdm::Workspace description #{n}"
  end

  sequence :mdm_workspace_name do |n|
    "Mdm::Workspace Name #{n}"
  end
end