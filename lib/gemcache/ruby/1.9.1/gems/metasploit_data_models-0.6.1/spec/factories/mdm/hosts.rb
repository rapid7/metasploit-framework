FactoryGirl.define do
  factory :mdm_host, :class => Mdm::Host do
    #
    # Associations
    #
    association :workspace, :factory => :mdm_workspace

    #
    # Attributes
    #
    address { generate :mdm_ipv4_address }
    name { generate :mdm_host_name }
  end

  sequence :mdm_host_name do |n|
    "mdm_host_#{n}"
  end
end