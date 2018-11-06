FactoryBot.define do
  sequence(:session_id)

  factory :metasploit_data_models_module_run, class: MetasploitDataModels::ModuleRun do

    association :user, factory: :mdm_user

    trait :failed do
      status MetasploitDataModels::ModuleRun::FAIL
    end

    trait :exploited do
      status MetasploitDataModels::ModuleRun::SUCCEED
    end

    trait :error do
      status MetasploitDataModels::ModuleRun::ERROR
    end

    attempted_at Time.now
    session_id 1
    port { generate :port }
    proto "tcp"
    fail_detail { generate :module_run_fail_detail }
    status MetasploitDataModels::ModuleRun::SUCCEED
    username "joefoo"
    module_fullname { generate :module_run_module_fullname }
  end

  sequence :module_run_module_fullname do |n|
    "exploit/windows/happy-stack-smasher-#{n}"
  end

  sequence :module_run_fail_detail do |n|
    "MetasploitDataModels::ModuleRun#fail_detail #{n}"
  end


end

