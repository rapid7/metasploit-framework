FactoryBot.define do
  factory :metasploit_credential_origin_service,
          class: Metasploit::Credential::Origin::Service do
    transient do
      module_type { generate :metasploit_credential_origin_service_module_type }
      reference_name { generate :metasploit_credential_origin_service_reference_name }
    end

    association :service, factory: :mdm_service

    module_full_name { "#{module_type}/#{reference_name}" }
  end

  metasploit_credential_origin_service_module_types = [
      'auxiliary',
      'exploit'
  ]
  sequence :metasploit_credential_origin_service_module_type, metasploit_credential_origin_service_module_types.cycle

  sequence :metasploit_credential_origin_service_reference_name do |n|
    "metasploit/credential/origin/service/reference/name#{n}"
  end
end
