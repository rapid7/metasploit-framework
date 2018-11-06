# Read about factories at https://github.com/thoughtbot/factory_bot

FactoryBot.define do
  factory :mdm_task_session, :class => 'Mdm::TaskSession' do
    association :task, :factory => :mdm_task
    association :session, :factory => :mdm_session
  end
end
