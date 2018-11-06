# Read about factories at https://github.com/thoughtbot/factory_bot

FactoryBot.define do
  factory :mdm_task_host, :class => 'Mdm::TaskHost' do

    association :task, :factory => :mdm_task
    association :host, :factory => :mdm_host
  end
end
