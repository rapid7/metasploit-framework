FactoryBot.define do
  factory :mdm_session, :aliases => [:session], :class => Mdm::Session do
    #
    # Associations
    #
    association :host, :factory => :mdm_host

    #
    # Attributes
    #
    opened_at { DateTime.now }
  end
end
