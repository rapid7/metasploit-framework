FactoryBot.define do
  factory :metasploit_credential_core,
          class: Metasploit::Credential::Core do
    transient do
      origin_factory { generate :metasploit_credential_core_origin_factory }
      private_factory { generate :metasploit_credential_core_private_factory }
      realm_factory { generate :metasploit_credential_core_realm_factory }
    end

    association :public, factory: :metasploit_credential_public

    origin { FactoryBot.build(origin_factory) }
    private { FactoryBot.build(private_factory) }
    realm { FactoryBot.build(realm_factory) }

    workspace {
      case origin
        when Metasploit::Credential::Origin::Import
          FactoryBot.build(:mdm_workspace)
        when Metasploit::Credential::Origin::Manual
          user = origin.user

          # an admin can use workspaces it is not a member of
          if user.admin
            FactoryBot.build(:mdm_workspace)
          else
            origin.user.workspaces.sample
          end
        when Metasploit::Credential::Origin::Service
          origin.service.host.workspace
        when Metasploit::Credential::Origin::Session
          origin.session.host.workspace
      end
    }

    factory :metasploit_credential_core_import do
      transient do
        origin_factory :metasploit_credential_origin_import
      end
    end

    factory :metasploit_credential_core_manual do
      transient do
        origin_factory :metasploit_credential_origin_manual
      end
    end

    factory :metasploit_credential_core_service do
      transient do
        origin_factory :metasploit_credential_origin_service
      end
    end

    factory :metasploit_credential_core_session do
      transient do
        origin_factory :metasploit_credential_origin_session
      end
    end
  end

  metasploit_credential_core_private_factories = [
      :metasploit_credential_password,
      :metasploit_credential_nonreplayable_hash,
      :metasploit_credential_ntlm_hash,
      :metasploit_credential_ssh_key
  ]
  sequence :metasploit_credential_core_private_factory, metasploit_credential_core_private_factories.cycle

  metasploit_credential_core_origin_factories = [
      :metasploit_credential_origin_import,
      :metasploit_credential_origin_manual,
      :metasploit_credential_origin_service,
      :metasploit_credential_origin_session
  ]
  sequence :metasploit_credential_core_origin_factory, metasploit_credential_core_origin_factories.cycle

  metasploit_credential_core_realm_factories = [
      :metasploit_credential_active_directory_domain,
      :metasploit_credential_oracle_system_identifier,
      :metasploit_credential_postgresql_database
  ]
  sequence :metasploit_credential_core_realm_factory, metasploit_credential_core_realm_factories.cycle
end
