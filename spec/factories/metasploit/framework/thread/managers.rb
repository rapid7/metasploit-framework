FactoryGirl.define do
  factory :metasploit_framework_thread_manager,
          class: Metasploit::Framework::Thread::Manager,
          traits: [
              :metasploit_model_base
          ] do
    association :framework, factory: :msf_simple_framework
  end
end