FactoryBot.define do
  factory :mdm_task, :aliases => [:task], :class => 'Mdm::Task' do
    #
    # Associations
    #
    association :workspace, :factory => :mdm_workspace

    #
    # Attributes
    #
    created_at { Time.now }
    updated_at { Time.now }


  end
end
