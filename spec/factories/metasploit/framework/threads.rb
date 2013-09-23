FactoryGirl.define do
  factory :metasploit_framework_thread,
          class: Metasploit::Framework::Thread,
          traits: [
              :metasploit_model_base
          ] do
    backtrace { caller }
    block { ->(*args) { args } }
    critical { false }
    name { generate :metasploit_framework_thread_name }
    spawned_at { Time.now }
  end

  sequence :metasploit_framework_thread_name do |n|
    "Metasploit::Framework::Thread ##{n}"
  end
end