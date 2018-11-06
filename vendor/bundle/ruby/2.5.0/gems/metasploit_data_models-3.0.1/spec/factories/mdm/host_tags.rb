FactoryBot.define do
  factory :mdm_host_tag, :class => Mdm::HostTag do
    #
    # Associations
    #
    association :host, :factory => :mdm_host
    association :tag, :factory => :mdm_tag
  end
end
