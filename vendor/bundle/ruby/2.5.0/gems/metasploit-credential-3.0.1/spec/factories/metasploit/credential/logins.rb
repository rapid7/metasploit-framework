FactoryBot.define do
  factory :metasploit_credential_login,
          class: Metasploit::Credential::Login do
    transient do
      host {
        FactoryBot.build(
          :mdm_host, workspace: workspace
        )
      }
      workspace { core.workspace }
    end

    access_level { generate :metasploit_credential_login_access_level }

    association :core, factory: :metasploit_credential_core

    last_attempted_at {
      unless status == Metasploit::Model::Login::Status::UNTRIED
        DateTime.now.utc
      end
    }
    service {
      FactoryBot.build(
          :mdm_service,
          host: host
      )
    }

    status { generate :metasploit_credential_login_status }
  end

  sequence :metasploit_credential_login_access_level do |n|
    "metasploit_credential_login_access_level#{n}"
  end

  sequence :metasploit_credential_login_status, Metasploit::Model::Login::Status::ALL.cycle
end
