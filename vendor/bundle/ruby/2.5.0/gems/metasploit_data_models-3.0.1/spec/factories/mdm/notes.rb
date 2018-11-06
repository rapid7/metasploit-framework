FactoryBot.define do
  factory :mdm_note, :aliases => [:note], :class => Mdm::Note do
    #
    # Associations
    #
    association :workspace, :factory => :mdm_workspace
    association :host, :factory => :mdm_host
    association :service, :factory => :mdm_service


  end
end
