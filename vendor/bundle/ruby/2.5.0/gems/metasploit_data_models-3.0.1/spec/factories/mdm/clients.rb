FactoryBot.define do
  factory :mdm_client, :class => Mdm::Client do
    #
    # Associations
    #
    association :host, :factory => :mdm_host
  end
end
