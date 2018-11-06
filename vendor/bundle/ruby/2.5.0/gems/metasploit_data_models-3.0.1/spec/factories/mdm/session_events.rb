FactoryBot.define do
  factory :mdm_session_event, :aliases => [:session_event], :class => Mdm::SessionEvent do
    #
    # Associations
    #
    association :session, :factory => :mdm_session
  end
end
