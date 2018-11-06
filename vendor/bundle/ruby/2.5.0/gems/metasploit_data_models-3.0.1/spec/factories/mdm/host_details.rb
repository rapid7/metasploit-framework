FactoryBot.define do
  factory :mdm_host_detail, :class => Mdm::HostDetail do
    #
    # Associations
    #
    association :host, :factory => :mdm_host
  end
end
