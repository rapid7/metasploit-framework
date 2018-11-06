FactoryBot.define do
  factory :mdm_vuln, :class => Mdm::Vuln do
    name { generate :mdm_vuln_name }

    trait :host do
      association :host, :factory => :mdm_host
    end

    trait :service do
      association :service, :factory => :mdm_service
    end

    factory :mdm_host_vuln, :traits => [:host]
    factory :mdm_service_vuln, :traits => [:service]
  end

  sequence :mdm_vuln_name do |n|
    "Mdm::Vuln#name #{n}"
  end
end
