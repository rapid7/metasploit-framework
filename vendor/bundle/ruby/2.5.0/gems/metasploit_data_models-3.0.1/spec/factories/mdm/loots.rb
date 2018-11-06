FactoryBot.define do
  factory :mdm_loot, :aliases => [:loot], :class => Mdm::Loot do
    #
    # Associations
    #
    association :service, :factory => :mdm_service
    association :workspace, :factory => :mdm_workspace
    association :host, :factory => :mdm_host

  end
end
