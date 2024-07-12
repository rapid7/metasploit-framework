require 'rspec'

RSpec.describe Msf::Post::Azure do
  subject do
    described_mixin = described_class
    klass = Class.new do
      include described_mixin
    end
    klass.allocate
  end

  azure_profile = {
    'subscriptions' => [
      {
        'id' => '11111111-1111-1111-1111-111111111111',
        'name' => 'N/A(tenant level account)',
        'state' => 'Enabled',
        'user' => {
          'name' => 'example@example.onmicrosoft.com',
          'type' => 'user'
        }, 'isDefault' => false, 'tenantId' => '11111111-1111-1111-1111-111111111111',
        'environmentName' => 'AzureCloud'
      }, {
        'id' => '11111111-1111-1111-1111-111111111111',
        'name' => 'Example',
        'state' => 'Enabled',
        'user' => {
          'name' => '11111111-1111-1111-1111-111111111111',
          'type' => 'servicePrincipal'
        }, 'isDefault' => true, 'tenantId' => '11111111-1111-1111-1111-111111111111',
        'environmentName' => 'AzureCloud',
        'homeTenantId' => '11111111-1111-1111-1111-111111111111',
        'managedByTenants' => []
      }
    ], 'installationId' => '11111111-1111-1111-1111-111111111111'
  }

  # https://github.com/rapid7/metasploit-framework/pull/10113#issuecomment-2144883991
  # azcontext.json generated via Save-AzContext

  azure_context = {
    'DefaultContextKey' => 'Example (aaaaaaaa-1111-1111-aaaa-111111111111) - aaaaaaaa-1111-1111-aaaa-111111111111 - example@example.onmicrosoft.com',
    'EnvironmentTable' => {},
    'Contexts' => {
      'Example (aaaaaaaa-1111-1111-aaaa-111111111111) - aaaaaaaa-1111-1111-aaaa-111111111111 - example@example.onmicrosoft.com' => {
        'Account' => {
          'Id' => 'example@example.onmicrosoft.com',
          'Credential' => nil,
          'Type' => 'User',
          'TenantMap' => {},
          'ExtendedProperties' => {
            'HomeAccountId' => '1aaa1111-a111-1a11-a111-1111a1a11a11.aaaaaaaa-1111-1111-aaaa-111111111111',
            'Subscriptions' => 'aaaaaaaa-1111-1111-aaaa-111111111111',
            'Tenants' => 'aaaaaaaa-1111-1111-aaaa-111111111111'
          }
        },
        'Tenant' => {
          'Id' => 'aaaaaaaa-1111-1111-aaaa-111111111111',
          'Directory' => nil,
          'IsHome' => true,
          'ExtendedProperties' => {}
        },
        'Subscription' => {
          'Id' => 'aaaaaaaa-1111-1111-aaaa-111111111111',
          'Name' => 'Example',
          'State' => 'Enabled',
          'ExtendedProperties' => {
            'SubscriptionPolices' => '{"locationPlacementId":"Public_2014-09-01","quotaId":"PayAsYouGo_2014-09-01","spendingLimit":"Off"}',
            'Account' => 'example@example.onmicrosoft.com',
            'AuthorizationSource' => 'RoleBased',
            'HomeTenant' => 'aaaaaaaa-1111-1111-aaaa-111111111111',
            'Tenants' => 'aaaaaaaa-1111-1111-aaaa-111111111111',
            'Environment' => 'AzureCloud'
          }
        },
        'Environment' => {
          'Name' => 'AzureCloud',
          'Type' => 'User-defined',
          'OnPremise' => false,
          'ServiceManagementUrl' => 'https://management.core.windows.net/',
          'ResourceManagerUrl' => 'https://management.azure.com/',
          'ManagementPortalUrl' => 'https://portal.azure.com/',
          'PublishSettingsFileUrl' => 'https://go.microsoft.com/fwlink/?LinkID=301775',
          'ActiveDirectoryAuthority' => 'https://login.microsoftonline.com/',
          'GalleryUrl' => 'https://gallery.azure.com/',
          'GraphUrl' => 'https://graph.windows.net/',
          'ActiveDirectoryServiceEndpointResourceId' => 'https://management.core.windows.net/',
          'StorageEndpointSuffix' => 'core.windows.net',
          'SqlDatabaseDnsSuffix' => '.database.windows.net',
          'TrafficManagerDnsSuffix' => 'trafficmanager.net',
          'AzureKeyVaultDnsSuffix' => 'vault.azure.net',
          'AzureKeyVaultServiceEndpointResourceId' => 'https://vault.azure.net',
          'GraphEndpointResourceId' => 'https://graph.windows.net/',
          'DataLakeEndpointResourceId' => 'https://datalake.azure.net/',
          'BatchEndpointResourceId' => 'https://batch.core.windows.net/',
          'AzureDataLakeAnalyticsCatalogAndJobEndpointSuffix' => 'azuredatalakeanalytics.net',
          'AzureDataLakeStoreFileSystemEndpointSuffix' => 'azuredatalakestore.net',
          'AdTenant' => 'Common',
          'ContainerRegistryEndpointSuffix' => 'azurecr.io',
          'VersionProfiles' => [],
          'ExtendedProperties' => {
            'OperationalInsightsEndpoint' => 'https://api.loganalytics.io/v1',
            'OperationalInsightsEndpointResourceId' => 'https://api.loganalytics.io',
            'AzureAnalysisServicesEndpointSuffix' => 'asazure.windows.net',
            'AnalysisServicesEndpointResourceId' => 'https://region.asazure.windows.net',
            'AzureAttestationServiceEndpointSuffix' => 'attest.azure.net',
            'AzureAttestationServiceEndpointResourceId' => 'https://attest.azure.net',
            'AzureSynapseAnalyticsEndpointSuffix' => 'dev.azuresynapse.net',
            'AzureSynapseAnalyticsEndpointResourceId' => 'https://dev.azuresynapse.net',
            'ManagedHsmServiceEndpointResourceId' => 'https://managedhsm.azure.net',
            'ManagedHsmServiceEndpointSuffix' => 'managedhsm.azure.net',
            'MicrosoftGraphEndpointResourceId' => 'https://graph.microsoft.com/',
            'MicrosoftGraphUrl' => 'https://graph.microsoft.com',
            'AzurePurviewEndpointSuffix' => 'purview.azure.net',
            'AzurePurviewEndpointResourceId' => 'https://purview.azure.net'
          }
        },
        'VersionProfile' => nil,
        'TokenCache' => {
          'CacheData' => 'eyd0aGlzX3dhc19hX3JlYWxseV9sb25nX2Jhc2U2NF9lbmNvZGVkX2pzb24nOidvYmplY3QnfQ=='
        },
        'ExtendedProperties' => {}
      }
    },
    'ExtendedProperties' => {}
  }

  # c:\Users\example\.Azure\AzureRmContext.json generated June 4, 2024
  # we currently don't pull anything from Environment, but in the examples I found, they were all the same. Leaving the first one
  # and removing the rest for simplicity of this test
  # service principal secret saving can be disabled: https://techcommunity.microsoft.com/t5/windows-powershell/warning-the-provided-service-principal-secret-will-be-included/m-p/2263253/highlight/true#M2447
  azure_rm_context = {
    'DefaultContextKey' => 'Example (aaaaaaaa-1111-1111-aaaa-111111111111) - aaaaaaaa-1111-1111-aaaa-111111111111 - aaaaaaaa-1111-1111-aaaa-111111111111',
    'EnvironmentTable' => {},
    'Contexts' => {
      'Example (aaaaaaaa-1111-1111-aaaa-111111111111) - aaaaaaaa-1111-1111-aaaa-111111111111 - user1@example.onmicrosoft.com' => {
        'Account' => {
          'Id' => 'user1@example.onmicrosoft.com',
          'Credential' => nil,
          'Type' => 'User',
          'TenantMap' => {},
          'ExtendedProperties' => {
            'UsePasswordAuth' => 'true',
            'HomeAccountId' => 'aaaaaaaa-1111-1111-aaaa-111111111111.aaaaaaaa-1111-1111-aaaa-111111111111',
            'Subscriptions' => 'aaaaaaaa-1111-1111-aaaa-111111111111',
            'Tenants' => 'aaaaaaaa-1111-1111-aaaa-111111111111'
          }
        },
        'Tenant' => {
          'Id' => 'aaaaaaaa-1111-1111-aaaa-111111111111',
          'Directory' => nil,
          'IsHome' => true,
          'ExtendedProperties' => {}
        },
        'Subscription' => {
          'Id' => 'aaaaaaaa-1111-1111-aaaa-111111111111',
          'Name' => 'Example',
          'State' => 'Enabled',
          'ExtendedProperties' => {
            'Account' => 'user1@example.onmicrosoft.com',
            'SubscriptionPolices' => '{"locationPlacementId":"Public_2014-09-01","quotaId":"PayAsYouGo_2014-09-01","spendingLimit":"Off"}',
            'HomeTenant' => 'aaaaaaaa-1111-1111-aaaa-111111111111',
            'AuthorizationSource' => 'RoleBased',
            'Tenants' => 'aaaaaaaa-1111-1111-aaaa-111111111111',
            'Environment' => 'AzureCloud'
          }
        },
        'Environment' => {
          'Name' => 'AzureCloud',
          'Type' => 'Built-in',
          'OnPremise' => false,
          'ServiceManagementUrl' => 'https://management.core.windows.net/',
          'ResourceManagerUrl' => 'https://management.azure.com/',
          'ManagementPortalUrl' => 'https://portal.azure.com/',
          'PublishSettingsFileUrl' => 'https://go.microsoft.com/fwlink/?LinkID=301775',
          'ActiveDirectoryAuthority' => 'https://login.microsoftonline.com/',
          'GalleryUrl' => 'https://gallery.azure.com/',
          'GraphUrl' => 'https://graph.windows.net/',
          'ActiveDirectoryServiceEndpointResourceId' => 'https://management.core.windows.net/',
          'StorageEndpointSuffix' => 'core.windows.net',
          'SqlDatabaseDnsSuffix' => '.database.windows.net',
          'TrafficManagerDnsSuffix' => 'trafficmanager.net',
          'AzureKeyVaultDnsSuffix' => 'vault.azure.net',
          'AzureKeyVaultServiceEndpointResourceId' => 'https://vault.azure.net',
          'GraphEndpointResourceId' => 'https://graph.windows.net/',
          'DataLakeEndpointResourceId' => 'https://datalake.azure.net/',
          'BatchEndpointResourceId' => 'https://batch.core.windows.net/',
          'AzureDataLakeAnalyticsCatalogAndJobEndpointSuffix' => 'azuredatalakeanalytics.net',
          'AzureDataLakeStoreFileSystemEndpointSuffix' => 'azuredatalakestore.net',
          'AdTenant' => 'Common',
          'ContainerRegistryEndpointSuffix' => 'azurecr.io',
          'VersionProfiles' => [],
          'ExtendedProperties' => {
            'OperationalInsightsEndpoint' => 'https://api.loganalytics.io/v1',
            'OperationalInsightsEndpointResourceId' => 'https://api.loganalytics.io',
            'AzureAnalysisServicesEndpointSuffix' => 'asazure.windows.net',
            'AnalysisServicesEndpointResourceId' => 'https://region.asazure.windows.net',
            'AzureAttestationServiceEndpointSuffix' => 'attest.azure.net',
            'AzureAttestationServiceEndpointResourceId' => 'https://attest.azure.net',
            'AzureSynapseAnalyticsEndpointSuffix' => 'dev.azuresynapse.net',
            'AzureSynapseAnalyticsEndpointResourceId' => 'https://dev.azuresynapse.net',
            'ManagedHsmServiceEndpointResourceId' => 'https://managedhsm.azure.net',
            'ManagedHsmServiceEndpointSuffix' => 'managedhsm.azure.net',
            'MicrosoftGraphEndpointResourceId' => 'https://graph.microsoft.com/',
            'MicrosoftGraphUrl' => 'https://graph.microsoft.com',
            'AzurePurviewEndpointSuffix' => 'purview.azure.net',
            'AzurePurviewEndpointResourceId' => 'https://purview.azure.net'
          }
        },
        'VersionProfile' => nil,
        'TokenCache' => {
          'CacheData' => nil
        },
        'ExtendedProperties' => {}
      },
      'Example (aaaaaaaa-1111-1111-aaaa-111111111111) - aaaaaaaa-1111-1111-aaaa-111111111111 - aaaaaaaa-1111-1111-aaaa-111111111111' => {
        'Account' => {
          'Id' => 'aaaaaaaa-1111-1111-aaaa-111111111111',
          'Credential' => nil,
          'Type' => 'ServicePrincipal',
          'TenantMap' => {},
          'ExtendedProperties' => {
            'Subscriptions' => 'aaaaaaaa-1111-1111-aaaa-111111111111',
            'Tenants' => 'aaaaaaaa-1111-1111-aaaa-111111111111',
            'ServicePrincipalSecret' => 'aaA1A~aaA~a~a1AAA1AAAa1aAA1AA1A11AAAAaaa'
          }
        },
        'Tenant' => {
          'Id' => 'aaaaaaaa-1111-1111-aaaa-111111111111',
          'Directory' => nil,
          'IsHome' => true,
          'ExtendedProperties' => {}
        },
        'Subscription' => {
          'Id' => 'aaaaaaaa-1111-1111-aaaa-111111111111',
          'Name' => 'Example',
          'State' => 'Enabled',
          'ExtendedProperties' => {
            'SubscriptionPolices' => '{"locationPlacementId":"Public_2014-09-01","quotaId":"PayAsYouGo_2014-09-01","spendingLimit":"Off"}',
            'Account' => 'aaaaaaaa-1111-1111-aaaa-111111111111',
            'AuthorizationSource' => 'RoleBased',
            'HomeTenant' => 'aaaaaaaa-1111-1111-aaaa-111111111111',
            'Tenants' => 'aaaaaaaa-1111-1111-aaaa-111111111111',
            'Environment' => 'AzureCloud'
          }
        },
        'Environment' => {},
        'VersionProfile' => nil,
        'TokenCache' => {
          'CacheData' => nil
        },
        'ExtendedProperties' => {}
      },
      'Example (aaaaaaaa-1111-1111-aaaa-111111111112) - aaaaaaaa-1111-1111-aaaa-111111111112 - aaaaaaaa-1111-1111-aaaa-111111111112' => {
        'Account' => {
          'Id' => 'aaaaaaaa-1111-1111-aaaa-111111111112',
          'Credential' => nil,
          'Type' => 'ServicePrincipal',
          'TenantMap' => {},
          'ExtendedProperties' => {
            'Subscriptions' => 'aaaaaaaa-1111-1111-aaaa-111111111112',
            'Tenants' => 'aaaaaaaa-1111-1111-aaaa-111111111112'
          }
        },
        'Tenant' => {
          'Id' => 'aaaaaaaa-1111-1111-aaaa-111111111112',
          'Directory' => nil,
          'IsHome' => true,
          'ExtendedProperties' => {}
        },
        'Subscription' => {
          'Id' => 'aaaaaaaa-1111-1111-aaaa-111111111112',
          'Name' => 'Example',
          'State' => 'Enabled',
          'ExtendedProperties' => {
            'SubscriptionPolices' => '{"locationPlacementId":"Public_2014-09-01","quotaId":"PayAsYouGo_2014-09-01","spendingLimit":"Off"}',
            'Account' => 'aaaaaaaa-1111-1111-aaaa-111111111112',
            'AuthorizationSource' => 'RoleBased',
            'HomeTenant' => 'aaaaaaaa-1111-1111-aaaa-111111111112',
            'Tenants' => 'aaaaaaaa-1111-1111-aaaa-111111111112',
            'Environment' => 'AzureCloud'
          }
        },
        'Environment' => {},
        'VersionProfile' => nil,
        'TokenCache' => {
          'CacheData' => nil
        },
        'ExtendedProperties' => {}
      },
      'Example (aaaaaaaa-1111-1111-aaaa-111111111122) - aaaaaaaa-1111-1111-aaaa-111111111111 - aaaaaaaa-1111-1111-aaaa-111111111111' => {
        'Account' => {
          'Id' => 'aaaaaaaa-1111-1111-aaaa-111111111122',
          'Credential' => nil,
          'Type' => 'AccessToken',
          'TenantMap' => {},
          'ExtendedProperties' => {
            'AccessToken' => 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IkwxS2ZLRklfam5YYndXYzIyeFp4dzFzVUhIMCIsImtpZCI6IkwxS2ZLRklfam5YYndXYzIyeFp4dzFzVUhIMCJ9.eyJhdWQiOiJodHRwczovL21hbmFnZW1lbnQuYXp1cmUuY29tIiwiaXNzIjoiaHR0cHM6Ly9zdHMud2luZG93cy5uZXQvMmQ1MGNiMjktNWY3Yi00OGE0LTg3Y2UtZmU3NWE5NDFhZGI2LyIsImlhdCI6MTcxNzQ3OTc5NywibmJmIjoxNzE3NDc5Nzk3LCJleHAiOjE3MTc1NjY0OTcsImFpbyI6IkUyTmdZSWliOGY3QndmVi8yUE5idXF3M1M0bzdBZ0E9IiwiYXBwaWQiOiIyZTkxYTRmZS1hMGYyLTQ2ZWUtODIxNC1mYTJmZjZhYTlhYmMiLCJhcHBpZGFjciI6IjIiLCJpZHAiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC8yZDUwY2IyOS01ZjdiLTQ4YTQtODdjZS1mZTc1YTk0MWFkYjYvIiwiaWR0eXAiOiJhcHAiLCJvaWQiOiIzMGU2NzcyNy1hOGI4LTQ4ZDktODMwMy1mMjQ2OWRmOTdjYjIiLCJyaCI6IjAuQUhBQUtjdFFMWHRmcEVpSHp2NTFxVUd0dGtaSWYza0F1dGRQdWtQYXdmajJNQlBFQUFBLiIsInN1YiI6IjMwZTY3NzI3LWE4YjgtNDhkOS04MzAzLWYyNDY5ZGY5N2NiMiIsInRpZCI6IjJkNTBjYjI5LTVmN2ItNDhhNC04N2NlLWZlNzVhOTQxYWRiNiIsInV0aSI6IkJ6YmQwak85ODBxR3lDZnFvOVZFQUEiLCJ2ZXIiOiIxLjAiLCJ4bXNfbWlyaWQiOiIvc3Vic2NyaXB0aW9ucy9iNDEzODI2Zi0xMDhkLTQwNDktOGMxMS1kNTJkNWQzODg3NjgvcmVzb3VyY2Vncm91cHMvUmVzZWFyY2gvcHJvdmlkZXJzL01pY3Jvc29mdC5XZWIvc2l0ZXMvdmF1bHRmcm9udGVuZCIsInhtc190Y2R0IjoxNjE1Mzc1NjI5fQ.HohJOJpOV-FVI5h5uCD3aRXm2CWQxxEPGeYhzmvbupRjwCJPQW7BQ4hiGdRk9KuEHiQ_WYrPNqVMOah948V2UjtqiDhPQg01H_qriQXhaIdmVa0ou7_ptZy9rmBR2iLLtUZFU3yCAEdNxJkdho-o5vlP6bWDld_EE5CTnqI0bO-PeVSNSAYFxAEmO4qqzMgqM-QzDOF9paMVnHDmiBhN76wUFIera6JRmeEjlkKiNknW_jsmgV_u4F5EoRmdlGivZ1DDYvpndOofuhvnCggK56HL8WNmIotmmNVQgUM0OPaorFhhxWmeJ9_wrPdFgI5uiTw9sE9gxOKj7Qdw1nxcHg',
            'GraphAccessToken' => '',
            'Subscriptions' => 'aaaaaaaa-1111-1111-aaaa-111111111111',
            'Tenants' => 'aaaaaaaa-1111-1111-aaaa-111111111111',
            'MicrosoftGraphAccessToken' => '',
            'KeyVault' => 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IkwxS2ZLRklfam5YYndXYzIyeFp4dzFzVUhIMCIsImtpZCI6IkwxS2ZLRklfam5YYndXYzIyeFp4dzFzVUhIMCJ9.eyJhdWQiOiJodHRwczovL3ZhdWx0LmF6dXJlLm5ldCIsImlzcyI6Imh0dHBzOi8vc3RzLndpbmRvd3MubmV0LzJkNTBjYjI5LTVmN2ItNDhhNC04N2NlLWZlNzVhOTQxYWRiNi8iLCJpYXQiOjE3MTc0Nzk5OTQsIm5iZiI6MTcxNzQ3OTk5NCwiZXhwIjoxNzE3NTY2Njk0LCJhaW8iOiJFMk5nWUNncXl2SCtJSnpqLzZDaE83U2wxTjRDQUE9PSIsImFwcGlkIjoiMmU5MWE0ZmUtYTBmMi00NmVlLTgyMTQtZmEyZmY2YWE5YWJjIiwiYXBwaWRhY3IiOiIyIiwiaWRwIjoiaHR0cHM6Ly9zdHMud2luZG93cy5uZXQvMmQ1MGNiMjktNWY3Yi00OGE0LTg3Y2UtZmU3NWE5NDFhZGI2LyIsIm9pZCI6IjMwZTY3NzI3LWE4YjgtNDhkOS04MzAzLWYyNDY5ZGY5N2NiMiIsInJoIjoiMC5BWEFBS2N0UUxYdGZwRWlIenY1MXFVR3R0am16cU0taWdocEhvOGtQd0w1NlFKUEVBQUEuIiwic3ViIjoiMzBlNjc3MjctYThiOC00OGQ5LTgzMDMtZjI0NjlkZjk3Y2IyIiwidGlkIjoiMmQ1MGNiMjktNWY3Yi00OGE0LTg3Y2UtZmU3NWE5NDFhZGI2IiwidXRpIjoia0s5UEpsN2doRUsyRlZiSmhKQlpBQSIsInZlciI6IjEuMCIsInhtc19taXJpZCI6Ii9zdWJzY3JpcHRpb25zL2I0MTM4MjZmLTEwOGQtNDA0OS04YzExLWQ1MmQ1ZDM4ODc2OC9yZXNvdXJjZWdyb3Vwcy9SZXNlYXJjaC9wcm92aWRlcnMvTWljcm9zb2Z0LldlYi9zaXRlcy92YXVsdGZyb250ZW5kIn0.AJqggInJNk_jsOZctiFkSfMirnWoeVbGdI-bZu-foscFHQ4e53Q9WX0agtSzi7P72U7XbqAL7A8ItBDkQ6rXLQhT7TjyyY7J8Jb97fY0oCL8xQi3eYkGTFIrJnXEN6JLY3BE5bhWxcmkaN61qSYnSLrph0qWn-cs32qa-SN1SbgwTTho2jUTYxDhkur1WBse_oaG-nIQDA-PoVT5nSkoNid8wQIIcmW7a-jFm2RnEqlbnPIF1H_i2wbBA4JA7Y0BW7Xbc1bX8kaZZAqM9hJ9wRAuYIzS2hz5uE3p-5rtkB6Vd0UGBx5OzRSO-kXVtu5cg42gB07gGw4zVwm47GLxBA'
          }
        },
        'Tenant' => {
          'Id' => 'aaaaaaaa-1111-1111-aaaa-111111111111',
          'Directory' => nil,
          'IsHome' => true,
          'ExtendedProperties' => {}
        },
        'Subscription' => {
          'Id' => 'aaaaaaaa-1111-1111-aaaa-111111111111',
          'Name' => 'Example',
          'State' => 'Enabled',
          'ExtendedProperties' => {
            'Account' => 'aaaaaaaa-1111-1111-aaaa-111111111111',
            'SubscriptionPolices' => '{"locationPlacementId":"Public_2014-09-01","quotaId":"PayAsYouGo_2014-09-01","spendingLimit":"Off"}',
            'HomeTenant' => 'aaaaaaaa-1111-1111-aaaa-111111111111',
            'AuthorizationSource' => 'RoleBased',
            'Tenants' => 'aaaaaaaa-1111-1111-aaaa-111111111111',
            'Environment' => 'AzureCloud'
          }
        },
        'Environment' => {},
        'VersionProfile' => nil,
        'TokenCache' => {
          'CacheData' => nil
        },
        'ExtendedProperties' => {}
      },
      'Example (aaaaaaaa-1111-1111-aaaa-111111111111) - aaaaaaaa-1111-1111-aaaa-111111111111 - test@example.onmicrosoft.com' => {
        'Account' => {
          'Id' => 'test@example.onmicrosoft.com',
          'Credential' => nil,
          'Type' => 'User',
          'TenantMap' => {},
          'ExtendedProperties' => {
            'HomeAccountId' => 'aaaaaaaa-1111-1111-aaaa-111111111111.aaaaaaaa-1111-1111-aaaa-111111111111',
            'Subscriptions' => 'aaaaaaaa-1111-1111-aaaa-111111111111',
            'Tenants' => 'aaaaaaaa-1111-1111-aaaa-111111111111'
          }
        },
        'Tenant' => {
          'Id' => 'aaaaaaaa-1111-1111-aaaa-111111111111',
          'Directory' => nil,
          'IsHome' => true,
          'ExtendedProperties' => {}
        },
        'Subscription' => {
          'Id' => 'aaaaaaaa-1111-1111-aaaa-111111111111',
          'Name' => 'Example',
          'State' => 'Enabled',
          'ExtendedProperties' => {
            'Account' => 'test@example.onmicrosoft.com',
            'SubscriptionPolices' => '{"locationPlacementId":"Public_2014-09-01","quotaId":"PayAsYouGo_2014-09-01","spendingLimit":"Off"}',
            'HomeTenant' => 'aaaaaaaa-1111-1111-aaaa-111111111111',
            'AuthorizationSource' => 'RoleBased',
            'Tenants' => 'aaaaaaaa-1111-1111-aaaa-111111111111',
            'Environment' => 'AzureCloud'
          }
        },
        'Environment' => {},
        'VersionProfile' => nil,
        'TokenCache' => {
          'CacheData' => nil
        },
        'ExtendedProperties' => {}
      },
      'Example (aaaaaaaa-1111-1111-aaaa-111111111111) - aaaaaaaa-1111-1111-aaaa-111111111111 - user2@example.onmicrosoft.com' => {
        'Account' => {
          'Id' => 'user2@example.onmicrosoft.com',
          'Credential' => nil,
          'Type' => 'User',
          'TenantMap' => {},
          'ExtendedProperties' => {
            'UsePasswordAuth' => 'true',
            'HomeAccountId' => 'aaaaaaaa-1111-1111-aaaa-111111111111.aaaaaaaa-1111-1111-aaaa-111111111111',
            'Subscriptions' => 'aaaaaaaa-1111-1111-aaaa-111111111111',
            'Tenants' => 'aaaaaaaa-1111-1111-aaaa-111111111111'
          }
        },
        'Tenant' => {
          'Id' => 'aaaaaaaa-1111-1111-aaaa-111111111111',
          'Directory' => nil,
          'IsHome' => true,
          'ExtendedProperties' => {}
        },
        'Subscription' => {
          'Id' => 'aaaaaaaa-1111-1111-aaaa-111111111111',
          'Name' => 'Example',
          'State' => 'Enabled',
          'ExtendedProperties' => {
            'SubscriptionPolices' => '{"locationPlacementId":"Public_2014-09-01","quotaId":"PayAsYouGo_2014-09-01","spendingLimit":"Off"}',
            'Account' => 'user2@example.onmicrosoft.com',
            'AuthorizationSource' => 'RoleBased',
            'HomeTenant' => 'aaaaaaaa-1111-1111-aaaa-111111111111',
            'Tenants' => 'aaaaaaaa-1111-1111-aaaa-111111111111',
            'Environment' => 'AzureCloud'
          }
        },
        'Environment' => {},
        'VersionProfile' => nil,
        'TokenCache' => {
          'CacheData' => nil
        },
        'ExtendedProperties' => {}
      },
      'aaaaaaaa-1111-1111-aaaa-111111111111 - aaaaaaaa-1111-1111-aaaa-111111111111' => {
        'Account' => {
          'Id' => 'aaaaaaaa-1111-1111-aaaa-111111111111',
          'Credential' => nil,
          'Type' => 'AccessToken',
          'TenantMap' => {},
          'ExtendedProperties' => {
            'AccessToken' => 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IkwxS2ZLRklfam5YYndXYzIyeFp4dzFzVUhIMCIsImtpZCI6IkwxS2ZLRklfam5YYndXYzIyeFp4dzFzVUhIMCJ9.eyJhdWQiOiJodHRwczovL21hbmFnZW1lbnQuYXp1cmUuY29tLyIsImlzcyI6Imh0dHBzOi8vc3RzLndpbmRvd3MubmV0LzJkNTBjYjI5LTVmN2ItNDhhNC04N2NlLWZlNzVhOTQxYWRiNi8iLCJpYXQiOjE3MTc0Mjk1NzMsIm5iZiI6MTcxNzQyOTU3MywiZXhwIjoxNzE3NTE2MjczLCJhaW8iOiJFMk5nWUxnU1V2cUI4OFVaMHd1UDF2V3VzNU5yQkFBPSIsImFwcGlkIjoiNjJlNDQ0MjYtNWM0Ni00ZTNjLThhODktZjQ2MWQ1ZDU4NmYyIiwiYXBwaWRhY3IiOiIyIiwiaWRwIjoiaHR0cHM6Ly9zdHMud2luZG93cy5uZXQvMmQ1MGNiMjktNWY3Yi00OGE0LTg3Y2UtZmU3NWE5NDFhZGI2LyIsImlkdHlwIjoiYXBwIiwib2lkIjoiZWE0YzNjMTctOGE1ZC00ZTFmLTk1NzctYjI5ZGZmZjA3MzBjIiwicmgiOiIwLkFYQUFLY3RRTFh0ZnBFaUh6djUxcVVHdHRrWklmM2tBdXRkUHVrUGF3ZmoyTUJQRUFBQS4iLCJzdWIiOiJlYTRjM2MxNy04YTVkLTRlMWYtOTU3Ny1iMjlkZmZmMDczMGMiLCJ0aWQiOiIyZDUwY2IyOS01ZjdiLTQ4YTQtODdjZS1mZTc1YTk0MWFkYjYiLCJ1dGkiOiJOamN1TVh3cHEwNlhCNGszSGJ1d0FRIiwidmVyIjoiMS4wIiwieG1zX21pcmlkIjoiL3N1YnNjcmlwdGlvbnMvYjQxMzgyNmYtMTA4ZC00MDQ5LThjMTEtZDUyZDVkMzg4NzY4L3Jlc291cmNlZ3JvdXBzL0lUL3Byb3ZpZGVycy9NaWNyb3NvZnQuV2ViL3NpdGVzL3Byb2Nlc3NmaWxlIiwieG1zX3RjZHQiOjE2MTUzNzU2Mjl9.AzQ9sQScF256AW-rL5582mfXpK4IBOIava-vGbZjiQJAvT3MViCmtG2vQxhxZg-Ih6tCVZu1ixuiQ5uBcXD4X6Pn8zHae1txXDrYJL5UkpjJdpnVD6I-jOf5TCAKaMjroJPTwIlz42DoarkaPkv9npzLW7WtOY0q0p1VK4tkGlrFKp9Hol5yza75GvMPR34Gan3ViAavT6BGja2nzippuLfXq5x65Mhh9xGjR3z8P8tJStcKGxXzagJsoBy-AYHCqkD_hsI-NegIKS6WTNyfF540RpnN-95WPOiyeBxFvemi3Et4xwxDmArTlq6H1qN0ZINKlOa48H7PxDvwqxuobA',
            'GraphAccessToken' => '',
            'Tenants' => 'aaaaaaaa-1111-1111-aaaa-111111111111',
            'MicrosoftGraphAccessToken' => 'eyJ0eXAiOiJKV1QiLCJub25jZSI6Ik5sWml1dG8waUZ4aXVKc1FGa2wxd3FtZ3RrWjBVZUpDTVdyTTVWUnZaek0iLCJhbGciOiJSUzI1NiIsIng1dCI6IkwxS2ZLRklfam5YYndXYzIyeFp4dzFzVUhIMCIsImtpZCI6IkwxS2ZLRklfam5YYndXYzIyeFp4dzFzVUhIMCJ9.eyJhdWQiOiJodHRwczovL2dyYXBoLm1pY3Jvc29mdC5jb20vIiwiaXNzIjoiaHR0cHM6Ly9zdHMud2luZG93cy5uZXQvMmQ1MGNiMjktNWY3Yi00OGE0LTg3Y2UtZmU3NWE5NDFhZGI2LyIsImlhdCI6MTcxNzQyOTU3NSwibmJmIjoxNzE3NDI5NTc1LCJleHAiOjE3MTc1MTYyNzUsImFpbyI6IkUyTmdZRkRQYkRpdStmV3V3WTRKOWJOUGVpLzRCQUE9IiwiYXBwX2Rpc3BsYXluYW1lIjoicHJvY2Vzc2ZpbGUiLCJhcHBpZCI6IjYyZTQ0NDI2LTVjNDYtNGUzYy04YTg5LWY0NjFkNWQ1ODZmMiIsImFwcGlkYWNyIjoiMiIsImlkcCI6Imh0dHBzOi8vc3RzLndpbmRvd3MubmV0LzJkNTBjYjI5LTVmN2ItNDhhNC04N2NlLWZlNzVhOTQxYWRiNi8iLCJpZHR5cCI6ImFwcCIsIm9pZCI6ImVhNGMzYzE3LThhNWQtNGUxZi05NTc3LWIyOWRmZmYwNzMwYyIsInJoIjoiMC5BWEFBS2N0UUxYdGZwRWlIenY1MXFVR3R0Z01BQUFBQUFBQUF3QUFBQUFBQUFBREVBQUEuIiwic3ViIjoiZWE0YzNjMTctOGE1ZC00ZTFmLTk1NzctYjI5ZGZmZjA3MzBjIiwidGVuYW50X3JlZ2lvbl9zY29wZSI6IkFTIiwidGlkIjoiMmQ1MGNiMjktNWY3Yi00OGE0LTg3Y2UtZmU3NWE5NDFhZGI2IiwidXRpIjoiRUR2aW5QMjRPRVc4YTd2VlBKenJBQSIsInZlciI6IjEuMCIsIndpZHMiOlsiMDk5N2ExZDAtMGQxZC00YWNiLWI0MDgtZDVjYTczMTIxZTkwIl0sInhtc190Y2R0IjoxNjE1Mzc1NjI5fQ.DQ6HXVY9Ik8aIgUfW2ATe6TotW5AgFSSUnYrp5i5DeELkk7A3Mr1cMMXGVW546r1mGswWzvD6rqQf1xeJx8zTz7y1Ne_hSeExmGjhcY9hPI1KVqhstC-za-_RrOe05xMSaVdDaMPM4zbZjjWYkonqbMD8hXHDO-k7khTjTDW-95q3nn2Zp3FMAKMw8GvTqKUn_T4WMi5LSEdXh2tn9MY5hdH2fK1dR0nuZPwsBr9Yr-jUDM10AFtQ41Plkpb7uHngYiQ_HxZhETHLdpt7kJw-uxPqF3VaYPNLBJqNHkbXFKqnITHIue_mBcqeR9J4_jlbl_QB6KSBYQx8s9X_uL5qw',
            'KeyVault' => ''
          }
        },
        'Tenant' => {
          'Id' => 'aaaaaaaa-1111-1111-aaaa-111111111111',
          'Directory' => nil,
          'IsHome' => true,
          'ExtendedProperties' => {}
        },
        'Subscription' => nil,
        'Environment' => {},
        'VersionProfile' => nil,
        'TokenCache' => {
          'CacheData' => nil
        },
        'ExtendedProperties' => {}
      },
      'Example (aaaaaaaa-1111-1111-aaaa-111111111144) - aaaaaaaa-1111-1111-aaaa-111111111111 - aaaaaaaa-1111-1111-aaaa-111111111111' => {
        'Account' => {
          'Id' => 'aaaaaaaa-1111-1111-aaaa-111111111144',
          'Credential' => nil,
          'Type' => 'AccessToken',
          'TenantMap' => {},
          'ExtendedProperties' => {
            'AccessToken' => 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IkwxS2ZLRklfam5YYndXYzIyeFp4dzFzVUhIMCIsImtpZCI6IkwxS2ZLRklfam5YYndXYzIyeFp4dzFzVUhIMCJ9.eyJhdWQiOiJodHRwczovL21hbmFnZW1lbnQuY29yZS53aW5kb3dzLm5ldC8iLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC8yZDUwY2IyOS01ZjdiLTQ4YTQtODdjZS1mZTc1YTk0MWFkYjYvIiwiaWF0IjoxNzE3NDM2NzMzLCJuYmYiOjE3MTc0MzY3MzMsImV4cCI6MTcxNzQ0MTUzNiwiYWNyIjoiMSIsImFpbyI6IkFUUUF5LzhXQUFBQTh4QTRXRzRSZS9QdHlMSE8wTnAxcEx1dTBZVTVWZEp4c09BZ2hDOUJiWkZJRVFKZGY0NTljalQxUFNXYmttWXIiLCJhbXIiOlsicHdkIl0sImFwcGlkIjoiMDRiMDc3OTUtOGRkYi00NjFhLWJiZWUtMDJmOWUxYmY3YjQ2IiwiYXBwaWRhY3IiOiIwIiwiZ3JvdXBzIjpbIjBjZTdkNDMyLTk0ZWEtNDQ4Yy1hMTQ5LTRhNTYzOTYzNTZiYiIsImU2ODcwNzgzLTEzNzgtNDA3OC1iMjQyLTg0YzA4YzZkYzBkNyJdLCJpZHR5cCI6InVzZXIiLCJpcGFkZHIiOiI1MS4yMTAuMS4yMzkiLCJuYW1lIjoiTWFyayBELiBXYWxkZW4iLCJvaWQiOiJmNjZlMTMzYy1iZDAxLTRiMGItYjNiNy03Y2Q5NDlmZDQ1ZjMiLCJwdWlkIjoiMTAwMzIwMDEyMEQ0Q0U0QiIsInJoIjoiMC5BWEFBS2N0UUxYdGZwRWlIenY1MXFVR3R0a1pJZjNrQXV0ZFB1a1Bhd2ZqMk1CUEVBQ2MuIiwic2NwIjoidXNlcl9pbXBlcnNvbmF0aW9uIiwic3ViIjoiYWpXYVBjS0JMUXZoTk1YMWRMcEtHdl95cUdTNHF6Q0ZBem1QQmNldVp6VSIsInRpZCI6IjJkNTBjYjI5LTVmN2ItNDhhNC04N2NlLWZlNzVhOTQxYWRiNiIsInVuaXF1ZV9uYW1lIjoiTWFya0RXYWxkZW5AZGVmY29ycGhxLm9ubWljcm9zb2Z0LmNvbSIsInVwbiI6Ik1hcmtEV2FsZGVuQGRlZmNvcnBocS5vbm1pY3Jvc29mdC5jb20iLCJ1dGkiOiJBTGFDTTdkai1VbWxsTFBuTVBmbkFRIiwidmVyIjoiMS4wIiwid2lkcyI6WyI5Yjg5NWQ5Mi0yY2QzLTQ0YzctOWQwMi1hNmFjMmQ1ZWE1YzMiLCJiNzlmYmY0ZC0zZWY5LTQ2ODktODE0My03NmIxOTRlODU1MDkiXSwieG1zX3RjZHQiOjE2MTUzNzU2Mjl9.Y5rRF-vwImsUEaaZS4GcSc_PBTCxLvn7UZoxqOkljKHawMCxjExCqxU3BpM9l1jgBncI4rEOF5VD6htgzRXBnOJdtwxrEp5AB_WKOhisfK6jfgRmgL1Z-DbuKIAjnCmWCcQv1Pi0r6ltXW_8EU_OFKtX0xtKNwsDdRkWHUTp8D62Ogr-KtZAxul1NhKwqGUQUWlS1N7_Q8wO4hGslJ_cve8GYAjgvWWoyKsuJcV1xKa4z4EfRjXQ-fCxFMZ3Evqp4KQoITXD_0_gIFrRHTSyUVy1E4vg5_F_C-CLyHzWQL6ss80NeL0IvAcwLBz3I_jTV1QzsHbHSH2-kGbLj_-XNg',
            'GraphAccessToken' => 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IkwxS2ZLRklfam5YYndXYzIyeFp4dzFzVUhIMCIsImtpZCI6IkwxS2ZLRklfam5YYndXYzIyeFp4dzFzVUhIMCJ9.eyJhdWQiOiJodHRwczovL2dyYXBoLndpbmRvd3MubmV0LyIsImlzcyI6Imh0dHBzOi8vc3RzLndpbmRvd3MubmV0LzJkNTBjYjI5LTVmN2ItNDhhNC04N2NlLWZlNzVhOTQxYWRiNi8iLCJpYXQiOjE3MTc0MzU4MzYsIm5iZiI6MTcxNzQzNTgzNiwiZXhwIjoxNzE3NDQwMzIxLCJhY3IiOiIxIiwiYWlvIjoiQVRRQXkvOFdBQUFBbFRkbmxMUnp5bkNoWHhhZTQzUVJuS0FUb0hCa2xObTdLcC96QmFvdm9CVXhPZG1uOW4yY01LSUVZYTVzYjdrRCIsImFtciI6WyJwd2QiXSwiYXBwaWQiOiIwNGIwNzc5NS04ZGRiLTQ2MWEtYmJlZS0wMmY5ZTFiZjdiNDYiLCJhcHBpZGFjciI6IjAiLCJpcGFkZHIiOiI1MS4yMTAuMS4yMzkiLCJuYW1lIjoiTWFyayBELiBXYWxkZW4iLCJvaWQiOiJmNjZlMTMzYy1iZDAxLTRiMGItYjNiNy03Y2Q5NDlmZDQ1ZjMiLCJwdWlkIjoiMTAwMzIwMDEyMEQ0Q0U0QiIsInJoIjoiMC5BWEFBS2N0UUxYdGZwRWlIenY1MXFVR3R0Z0lBQUFBQUFBQUF3QUFBQUFBQUFBREVBQ2MuIiwic2NwIjoiNjJlOTAzOTQtNjlmNS00MjM3LTkxOTAtMDEyMTc3MTQ1ZTEwIiwic3ViIjoiWmoxUC0zY05mYzNXd3pJdTRRS1lBVVhzZnVmM3JCTElnajhfSEJXeEtybyIsInRlbmFudF9yZWdpb25fc2NvcGUiOiJBUyIsInRpZCI6IjJkNTBjYjI5LTVmN2ItNDhhNC04N2NlLWZlNzVhOTQxYWRiNiIsInVuaXF1ZV9uYW1lIjoiTWFya0RXYWxkZW5AZGVmY29ycGhxLm9ubWljcm9zb2Z0LmNvbSIsInVwbiI6Ik1hcmtEV2FsZGVuQGRlZmNvcnBocS5vbm1pY3Jvc29mdC5jb20iLCJ1dGkiOiJERkNVdzZsQWdFNk05NDJDTjg3YUFBIiwidmVyIjoiMS4wIn0.HoazTDqkWLWHNH_kbKuttqJ_gY-zaeK3guaNh1qZFM8miX3CdTTxlxfQyeo1F0G1dCQjq188qAGFzBxjQcPKC7ywFF-od122eI_l2ckeZTI44BDo2Vy-XoAXTaFakgm5ol-hFfc5dfikmu6Kgp0EQaUVIOOdIzqKuElYnx1qqSAHanxhWS7m44ASewOTkjiipkLhss_jGoMWcqSXgL2YxCsCtcv5UOOkCsq-V7XZ7bCuqnyfZ_waRNskNe7GgM_CsHmxn2PqKMbqqIoGC7Lcv7vOGW9YxWZVfxuxKnVq5k-VyzaoInlx5bTLNlxr_Ssqki1CpQMJmue_nwyDCiCpnw',
            'Subscriptions' => 'aaaaaaaa-1111-1111-aaaa-111111111111',
            'Tenants' => 'aaaaaaaa-1111-1111-aaaa-111111111111',
            'MicrosoftGraphAccessToken' => '',
            'KeyVault' => ''
          }
        },
        'Tenant' => {
          'Id' => 'aaaaaaaa-1111-1111-aaaa-111111111111',
          'Directory' => nil,
          'IsHome' => true,
          'ExtendedProperties' => {}
        },
        'Subscription' => {
          'Id' => 'aaaaaaaa-1111-1111-aaaa-111111111111',
          'Name' => 'Example',
          'State' => 'Enabled',
          'ExtendedProperties' => {
            'Account' => 'aaaaaaaa-1111-1111-aaaa-111111111111',
            'SubscriptionPolices' => '{"locationPlacementId":"Public_2014-09-01","quotaId":"PayAsYouGo_2014-09-01","spendingLimit":"Off"}',
            'HomeTenant' => 'aaaaaaaa-1111-1111-aaaa-111111111111',
            'AuthorizationSource' => 'RoleBased',
            'Tenants' => 'aaaaaaaa-1111-1111-aaaa-111111111111',
            'Environment' => 'AzureCloud'
          }
        },
        'Environment' => {},
        'VersionProfile' => nil,
        'TokenCache' => {
          'CacheData' => nil
        },
        'ExtendedProperties' => {}
      },
      'Example (aaaaaaaa-1111-1111-aaaa-111111111133) - aaaaaaaa-1111-1111-aaaa-111111111111 - aaaaaaaa-1111-1111-aaaa-111111111111' => {
        'Account' => {
          'Id' => 'aaaaaaaa-1111-1111-aaaa-111111111133',
          'Credential' => nil,
          'Type' => 'AccessToken',
          'TenantMap' => {},
          'ExtendedProperties' => {
            'AccessToken' => 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IkwxS2ZLRklfam5YYndXYzIyeFp4dzFzVUhIMCIsImtpZCI6IkwxS2ZLRklfam5YYndXYzIyeFp4dzFzVUhIMCJ9.eyJhdWQiOiJodHRwczovL21hbmFnZW1lbnQuYXp1cmUuY29tLyIsImlzcyI6Imh0dHBzOi8vc3RzLndpbmRvd3MubmV0LzJkNTBjYjI5LTVmN2ItNDhhNC04N2NlLWZlNzVhOTQxYWRiNi8iLCJpYXQiOjE3MTc0MTg3ODMsIm5iZiI6MTcxNzQxODc4MywiZXhwIjoxNzE3NTA1NDgzLCJhaW8iOiJFMk5nWUZpVkVWbXg0SkowMU5XaWwwRnZEVHFpQVE9PSIsImFwcGlkIjoiMDY0YWFmNTctMzBhZi00MWYwLTg0MGEtMGUyMWVkMTQ5OTQ2IiwiYXBwaWRhY3IiOiIyIiwiaWRwIjoiaHR0cHM6Ly9zdHMud2luZG93cy5uZXQvMmQ1MGNiMjktNWY3Yi00OGE0LTg3Y2UtZmU3NWE5NDFhZGI2LyIsImlkdHlwIjoiYXBwIiwib2lkIjoiY2M2N2M5MGQtZDllOS00MGQyLWI1MTEtOWQ1MmQ2NzY4MmFiIiwicmgiOiIwLkFYQUFLY3RRTFh0ZnBFaUh6djUxcVVHdHRrWklmM2tBdXRkUHVrUGF3ZmoyTUJQRUFBQS4iLCJzdWIiOiJjYzY3YzkwZC1kOWU5LTQwZDItYjUxMS05ZDUyZDY3NjgyYWIiLCJ0aWQiOiIyZDUwY2IyOS01ZjdiLTQ4YTQtODdjZS1mZTc1YTk0MWFkYjYiLCJ1dGkiOiJrZDBkanNYQWIwSzZGdEZJMzNvekFBIiwidmVyIjoiMS4wIiwieG1zX21pcmlkIjoiL3N1YnNjcmlwdGlvbnMvYjQxMzgyNmYtMTA4ZC00MDQ5LThjMTEtZDUyZDVkMzg4NzY4L3Jlc291cmNlZ3JvdXBzL0VuZ2luZWVyaW5nL3Byb3ZpZGVycy9NaWNyb3NvZnQuV2ViL3NpdGVzL2RlZmNvcnBocWNhcmVlciIsInhtc190Y2R0IjoiMTYxNTM3NTYyOSJ9.fdLyjWihy0Q8QPAJj0p_CRMqgj0_N87x4u7flu3Hogw1OzdFe4yA7IfeO3_pwTqezPdY2aihBHhlyBs4uX-pK8c_3_n3kjLOnAcizRFzhHhO5-dS4p_izapje9Eqq5NvoR6-v05CIPp2k1hL4Kww4wSLUNRLid6olmSG8S7nyfoFNicdYGo0YNEOqqMq8SkQpaWpmwPnLMpkIp1oZNUiJSSHxFOjj3typkxSFKde4acsqU8LaTCL1quP6oxWmPf2GwDYmz8K5pspL9O2YB-jbId6m_0Fw2omA1QJSh2_lUvEm2LQYDUksFXjC4mov0O3UYa68SFuMHVosY-aMA7BNg',
            'GraphAccessToken' => '',
            'Subscriptions' => 'aaaaaaaa-1111-1111-aaaa-111111111111',
            'Tenants' => 'aaaaaaaa-1111-1111-aaaa-111111111111',
            'MicrosoftGraphAccessToken' => '',
            'KeyVault' => ''
          }
        },
        'Tenant' => {
          'Id' => 'aaaaaaaa-1111-1111-aaaa-111111111111',
          'Directory' => nil,
          'IsHome' => true,
          'ExtendedProperties' => {}
        },
        'Subscription' => {
          'Id' => 'aaaaaaaa-1111-1111-aaaa-111111111111',
          'Name' => 'Example',
          'State' => 'Enabled',
          'ExtendedProperties' => {
            'SubscriptionPolices' => '{"locationPlacementId":"Public_2014-09-01","quotaId":"PayAsYouGo_2014-09-01","spendingLimit":"Off"}',
            'Account' => 'aaaaaaaa-1111-1111-aaaa-111111111111',
            'AuthorizationSource' => 'RoleBased',
            'HomeTenant' => 'aaaaaaaa-1111-1111-aaaa-111111111111',
            'Tenants' => 'aaaaaaaa-1111-1111-aaaa-111111111111',
            'Environment' => 'AzureCloud'
          }
        },
        'Environment' => {},
        'VersionProfile' => nil,
        'TokenCache' => {
          'CacheData' => nil
        },
        'ExtendedProperties' => {}
      }
    },
    'ExtendedProperties' => {}
  }

  context '.process_context_contents' do
    it 'should return empty on bad json content' do
      expect(subject.send(:process_context_contents, {})).to eql([])
    end

    it 'should return parsed content for azure_context file' do
      expect(subject.send(:process_context_contents, azure_context)).to eql([['example@example.onmicrosoft.com', 'User', nil, nil, nil, nil, nil]])
    end

    it 'should return parsed content for azure_rm_context file' do
      expect(subject.send(:process_context_contents, azure_rm_context)).to eql([
        ['user1@example.onmicrosoft.com', 'User', nil, nil, nil, nil, nil],
        ['aaaaaaaa-1111-1111-aaaa-111111111111', 'ServicePrincipal', nil, nil, nil, nil, 'aaA1A~aaA~a~a1AAA1AAAa1aAA1AA1A11AAAAaaa'],
        ['aaaaaaaa-1111-1111-aaaa-111111111112', 'ServicePrincipal', nil, nil, nil, nil, nil],
        [
          'aaaaaaaa-1111-1111-aaaa-111111111122', 'AccessToken',
          'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IkwxS2ZLRklfam5YYndXYzIyeFp4dzFzVUhIMCIsImtpZCI6IkwxS2ZLRklfam5YYndXYzIyeFp4dzFzVUhIMCJ9.eyJhdWQiOiJodHRwczovL21hbmFnZW1lbnQuYXp1cmUuY29tIiwiaXNzIjoiaHR0cHM6Ly9zdHMud2luZG93cy5uZXQvMmQ1MGNiMjktNWY3Yi00OGE0LTg3Y2UtZmU3NWE5NDFhZGI2LyIsImlhdCI6MTcxNzQ3OTc5NywibmJmIjoxNzE3NDc5Nzk3LCJleHAiOjE3MTc1NjY0OTcsImFpbyI6IkUyTmdZSWliOGY3QndmVi8yUE5idXF3M1M0bzdBZ0E9IiwiYXBwaWQiOiIyZTkxYTRmZS1hMGYyLTQ2ZWUtODIxNC1mYTJmZjZhYTlhYmMiLCJhcHBpZGFjciI6IjIiLCJpZHAiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC8yZDUwY2IyOS01ZjdiLTQ4YTQtODdjZS1mZTc1YTk0MWFkYjYvIiwiaWR0eXAiOiJhcHAiLCJvaWQiOiIzMGU2NzcyNy1hOGI4LTQ4ZDktODMwMy1mMjQ2OWRmOTdjYjIiLCJyaCI6IjAuQUhBQUtjdFFMWHRmcEVpSHp2NTFxVUd0dGtaSWYza0F1dGRQdWtQYXdmajJNQlBFQUFBLiIsInN1YiI6IjMwZTY3NzI3LWE4YjgtNDhkOS04MzAzLWYyNDY5ZGY5N2NiMiIsInRpZCI6IjJkNTBjYjI5LTVmN2ItNDhhNC04N2NlLWZlNzVhOTQxYWRiNiIsInV0aSI6IkJ6YmQwak85ODBxR3lDZnFvOVZFQUEiLCJ2ZXIiOiIxLjAiLCJ4bXNfbWlyaWQiOiIvc3Vic2NyaXB0aW9ucy9iNDEzODI2Zi0xMDhkLTQwNDktOGMxMS1kNTJkNWQzODg3NjgvcmVzb3VyY2Vncm91cHMvUmVzZWFyY2gvcHJvdmlkZXJzL01pY3Jvc29mdC5XZWIvc2l0ZXMvdmF1bHRmcm9udGVuZCIsInhtc190Y2R0IjoxNjE1Mzc1NjI5fQ.HohJOJpOV-FVI5h5uCD3aRXm2CWQxxEPGeYhzmvbupRjwCJPQW7BQ4hiGdRk9KuEHiQ_WYrPNqVMOah948V2UjtqiDhPQg01H_qriQXhaIdmVa0ou7_ptZy9rmBR2iLLtUZFU3yCAEdNxJkdho-o5vlP6bWDld_EE5CTnqI0bO-PeVSNSAYFxAEmO4qqzMgqM-QzDOF9paMVnHDmiBhN76wUFIera6JRmeEjlkKiNknW_jsmgV_u4F5EoRmdlGivZ1DDYvpndOofuhvnCggK56HL8WNmIotmmNVQgUM0OPaorFhhxWmeJ9_wrPdFgI5uiTw9sE9gxOKj7Qdw1nxcHg',
          '',
          '',
          'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IkwxS2ZLRklfam5YYndXYzIyeFp4dzFzVUhIMCIsImtpZCI6IkwxS2ZLRklfam5YYndXYzIyeFp4dzFzVUhIMCJ9.eyJhdWQiOiJodHRwczovL3ZhdWx0LmF6dXJlLm5ldCIsImlzcyI6Imh0dHBzOi8vc3RzLndpbmRvd3MubmV0LzJkNTBjYjI5LTVmN2ItNDhhNC04N2NlLWZlNzVhOTQxYWRiNi8iLCJpYXQiOjE3MTc0Nzk5OTQsIm5iZiI6MTcxNzQ3OTk5NCwiZXhwIjoxNzE3NTY2Njk0LCJhaW8iOiJFMk5nWUNncXl2SCtJSnpqLzZDaE83U2wxTjRDQUE9PSIsImFwcGlkIjoiMmU5MWE0ZmUtYTBmMi00NmVlLTgyMTQtZmEyZmY2YWE5YWJjIiwiYXBwaWRhY3IiOiIyIiwiaWRwIjoiaHR0cHM6Ly9zdHMud2luZG93cy5uZXQvMmQ1MGNiMjktNWY3Yi00OGE0LTg3Y2UtZmU3NWE5NDFhZGI2LyIsIm9pZCI6IjMwZTY3NzI3LWE4YjgtNDhkOS04MzAzLWYyNDY5ZGY5N2NiMiIsInJoIjoiMC5BWEFBS2N0UUxYdGZwRWlIenY1MXFVR3R0am16cU0taWdocEhvOGtQd0w1NlFKUEVBQUEuIiwic3ViIjoiMzBlNjc3MjctYThiOC00OGQ5LTgzMDMtZjI0NjlkZjk3Y2IyIiwidGlkIjoiMmQ1MGNiMjktNWY3Yi00OGE0LTg3Y2UtZmU3NWE5NDFhZGI2IiwidXRpIjoia0s5UEpsN2doRUsyRlZiSmhKQlpBQSIsInZlciI6IjEuMCIsInhtc19taXJpZCI6Ii9zdWJzY3JpcHRpb25zL2I0MTM4MjZmLTEwOGQtNDA0OS04YzExLWQ1MmQ1ZDM4ODc2OC9yZXNvdXJjZWdyb3Vwcy9SZXNlYXJjaC9wcm92aWRlcnMvTWljcm9zb2Z0LldlYi9zaXRlcy92YXVsdGZyb250ZW5kIn0.AJqggInJNk_jsOZctiFkSfMirnWoeVbGdI-bZu-foscFHQ4e53Q9WX0agtSzi7P72U7XbqAL7A8ItBDkQ6rXLQhT7TjyyY7J8Jb97fY0oCL8xQi3eYkGTFIrJnXEN6JLY3BE5bhWxcmkaN61qSYnSLrph0qWn-cs32qa-SN1SbgwTTho2jUTYxDhkur1WBse_oaG-nIQDA-PoVT5nSkoNid8wQIIcmW7a-jFm2RnEqlbnPIF1H_i2wbBA4JA7Y0BW7Xbc1bX8kaZZAqM9hJ9wRAuYIzS2hz5uE3p-5rtkB6Vd0UGBx5OzRSO-kXVtu5cg42gB07gGw4zVwm47GLxBA',
          nil
        ],
        ['test@example.onmicrosoft.com', 'User', nil, nil, nil, nil, nil],
        ['user2@example.onmicrosoft.com', 'User', nil, nil, nil, nil, nil],
        [
          'aaaaaaaa-1111-1111-aaaa-111111111111', 'AccessToken',
          'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IkwxS2ZLRklfam5YYndXYzIyeFp4dzFzVUhIMCIsImtpZCI6IkwxS2ZLRklfam5YYndXYzIyeFp4dzFzVUhIMCJ9.eyJhdWQiOiJodHRwczovL21hbmFnZW1lbnQuYXp1cmUuY29tLyIsImlzcyI6Imh0dHBzOi8vc3RzLndpbmRvd3MubmV0LzJkNTBjYjI5LTVmN2ItNDhhNC04N2NlLWZlNzVhOTQxYWRiNi8iLCJpYXQiOjE3MTc0Mjk1NzMsIm5iZiI6MTcxNzQyOTU3MywiZXhwIjoxNzE3NTE2MjczLCJhaW8iOiJFMk5nWUxnU1V2cUI4OFVaMHd1UDF2V3VzNU5yQkFBPSIsImFwcGlkIjoiNjJlNDQ0MjYtNWM0Ni00ZTNjLThhODktZjQ2MWQ1ZDU4NmYyIiwiYXBwaWRhY3IiOiIyIiwiaWRwIjoiaHR0cHM6Ly9zdHMud2luZG93cy5uZXQvMmQ1MGNiMjktNWY3Yi00OGE0LTg3Y2UtZmU3NWE5NDFhZGI2LyIsImlkdHlwIjoiYXBwIiwib2lkIjoiZWE0YzNjMTctOGE1ZC00ZTFmLTk1NzctYjI5ZGZmZjA3MzBjIiwicmgiOiIwLkFYQUFLY3RRTFh0ZnBFaUh6djUxcVVHdHRrWklmM2tBdXRkUHVrUGF3ZmoyTUJQRUFBQS4iLCJzdWIiOiJlYTRjM2MxNy04YTVkLTRlMWYtOTU3Ny1iMjlkZmZmMDczMGMiLCJ0aWQiOiIyZDUwY2IyOS01ZjdiLTQ4YTQtODdjZS1mZTc1YTk0MWFkYjYiLCJ1dGkiOiJOamN1TVh3cHEwNlhCNGszSGJ1d0FRIiwidmVyIjoiMS4wIiwieG1zX21pcmlkIjoiL3N1YnNjcmlwdGlvbnMvYjQxMzgyNmYtMTA4ZC00MDQ5LThjMTEtZDUyZDVkMzg4NzY4L3Jlc291cmNlZ3JvdXBzL0lUL3Byb3ZpZGVycy9NaWNyb3NvZnQuV2ViL3NpdGVzL3Byb2Nlc3NmaWxlIiwieG1zX3RjZHQiOjE2MTUzNzU2Mjl9.AzQ9sQScF256AW-rL5582mfXpK4IBOIava-vGbZjiQJAvT3MViCmtG2vQxhxZg-Ih6tCVZu1ixuiQ5uBcXD4X6Pn8zHae1txXDrYJL5UkpjJdpnVD6I-jOf5TCAKaMjroJPTwIlz42DoarkaPkv9npzLW7WtOY0q0p1VK4tkGlrFKp9Hol5yza75GvMPR34Gan3ViAavT6BGja2nzippuLfXq5x65Mhh9xGjR3z8P8tJStcKGxXzagJsoBy-AYHCqkD_hsI-NegIKS6WTNyfF540RpnN-95WPOiyeBxFvemi3Et4xwxDmArTlq6H1qN0ZINKlOa48H7PxDvwqxuobA',
          '',
          'eyJ0eXAiOiJKV1QiLCJub25jZSI6Ik5sWml1dG8waUZ4aXVKc1FGa2wxd3FtZ3RrWjBVZUpDTVdyTTVWUnZaek0iLCJhbGciOiJSUzI1NiIsIng1dCI6IkwxS2ZLRklfam5YYndXYzIyeFp4dzFzVUhIMCIsImtpZCI6IkwxS2ZLRklfam5YYndXYzIyeFp4dzFzVUhIMCJ9.eyJhdWQiOiJodHRwczovL2dyYXBoLm1pY3Jvc29mdC5jb20vIiwiaXNzIjoiaHR0cHM6Ly9zdHMud2luZG93cy5uZXQvMmQ1MGNiMjktNWY3Yi00OGE0LTg3Y2UtZmU3NWE5NDFhZGI2LyIsImlhdCI6MTcxNzQyOTU3NSwibmJmIjoxNzE3NDI5NTc1LCJleHAiOjE3MTc1MTYyNzUsImFpbyI6IkUyTmdZRkRQYkRpdStmV3V3WTRKOWJOUGVpLzRCQUE9IiwiYXBwX2Rpc3BsYXluYW1lIjoicHJvY2Vzc2ZpbGUiLCJhcHBpZCI6IjYyZTQ0NDI2LTVjNDYtNGUzYy04YTg5LWY0NjFkNWQ1ODZmMiIsImFwcGlkYWNyIjoiMiIsImlkcCI6Imh0dHBzOi8vc3RzLndpbmRvd3MubmV0LzJkNTBjYjI5LTVmN2ItNDhhNC04N2NlLWZlNzVhOTQxYWRiNi8iLCJpZHR5cCI6ImFwcCIsIm9pZCI6ImVhNGMzYzE3LThhNWQtNGUxZi05NTc3LWIyOWRmZmYwNzMwYyIsInJoIjoiMC5BWEFBS2N0UUxYdGZwRWlIenY1MXFVR3R0Z01BQUFBQUFBQUF3QUFBQUFBQUFBREVBQUEuIiwic3ViIjoiZWE0YzNjMTctOGE1ZC00ZTFmLTk1NzctYjI5ZGZmZjA3MzBjIiwidGVuYW50X3JlZ2lvbl9zY29wZSI6IkFTIiwidGlkIjoiMmQ1MGNiMjktNWY3Yi00OGE0LTg3Y2UtZmU3NWE5NDFhZGI2IiwidXRpIjoiRUR2aW5QMjRPRVc4YTd2VlBKenJBQSIsInZlciI6IjEuMCIsIndpZHMiOlsiMDk5N2ExZDAtMGQxZC00YWNiLWI0MDgtZDVjYTczMTIxZTkwIl0sInhtc190Y2R0IjoxNjE1Mzc1NjI5fQ.DQ6HXVY9Ik8aIgUfW2ATe6TotW5AgFSSUnYrp5i5DeELkk7A3Mr1cMMXGVW546r1mGswWzvD6rqQf1xeJx8zTz7y1Ne_hSeExmGjhcY9hPI1KVqhstC-za-_RrOe05xMSaVdDaMPM4zbZjjWYkonqbMD8hXHDO-k7khTjTDW-95q3nn2Zp3FMAKMw8GvTqKUn_T4WMi5LSEdXh2tn9MY5hdH2fK1dR0nuZPwsBr9Yr-jUDM10AFtQ41Plkpb7uHngYiQ_HxZhETHLdpt7kJw-uxPqF3VaYPNLBJqNHkbXFKqnITHIue_mBcqeR9J4_jlbl_QB6KSBYQx8s9X_uL5qw',
          '',
          nil
        ],
        [
          'aaaaaaaa-1111-1111-aaaa-111111111144', 'AccessToken',
          'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IkwxS2ZLRklfam5YYndXYzIyeFp4dzFzVUhIMCIsImtpZCI6IkwxS2ZLRklfam5YYndXYzIyeFp4dzFzVUhIMCJ9.eyJhdWQiOiJodHRwczovL21hbmFnZW1lbnQuY29yZS53aW5kb3dzLm5ldC8iLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC8yZDUwY2IyOS01ZjdiLTQ4YTQtODdjZS1mZTc1YTk0MWFkYjYvIiwiaWF0IjoxNzE3NDM2NzMzLCJuYmYiOjE3MTc0MzY3MzMsImV4cCI6MTcxNzQ0MTUzNiwiYWNyIjoiMSIsImFpbyI6IkFUUUF5LzhXQUFBQTh4QTRXRzRSZS9QdHlMSE8wTnAxcEx1dTBZVTVWZEp4c09BZ2hDOUJiWkZJRVFKZGY0NTljalQxUFNXYmttWXIiLCJhbXIiOlsicHdkIl0sImFwcGlkIjoiMDRiMDc3OTUtOGRkYi00NjFhLWJiZWUtMDJmOWUxYmY3YjQ2IiwiYXBwaWRhY3IiOiIwIiwiZ3JvdXBzIjpbIjBjZTdkNDMyLTk0ZWEtNDQ4Yy1hMTQ5LTRhNTYzOTYzNTZiYiIsImU2ODcwNzgzLTEzNzgtNDA3OC1iMjQyLTg0YzA4YzZkYzBkNyJdLCJpZHR5cCI6InVzZXIiLCJpcGFkZHIiOiI1MS4yMTAuMS4yMzkiLCJuYW1lIjoiTWFyayBELiBXYWxkZW4iLCJvaWQiOiJmNjZlMTMzYy1iZDAxLTRiMGItYjNiNy03Y2Q5NDlmZDQ1ZjMiLCJwdWlkIjoiMTAwMzIwMDEyMEQ0Q0U0QiIsInJoIjoiMC5BWEFBS2N0UUxYdGZwRWlIenY1MXFVR3R0a1pJZjNrQXV0ZFB1a1Bhd2ZqMk1CUEVBQ2MuIiwic2NwIjoidXNlcl9pbXBlcnNvbmF0aW9uIiwic3ViIjoiYWpXYVBjS0JMUXZoTk1YMWRMcEtHdl95cUdTNHF6Q0ZBem1QQmNldVp6VSIsInRpZCI6IjJkNTBjYjI5LTVmN2ItNDhhNC04N2NlLWZlNzVhOTQxYWRiNiIsInVuaXF1ZV9uYW1lIjoiTWFya0RXYWxkZW5AZGVmY29ycGhxLm9ubWljcm9zb2Z0LmNvbSIsInVwbiI6Ik1hcmtEV2FsZGVuQGRlZmNvcnBocS5vbm1pY3Jvc29mdC5jb20iLCJ1dGkiOiJBTGFDTTdkai1VbWxsTFBuTVBmbkFRIiwidmVyIjoiMS4wIiwid2lkcyI6WyI5Yjg5NWQ5Mi0yY2QzLTQ0YzctOWQwMi1hNmFjMmQ1ZWE1YzMiLCJiNzlmYmY0ZC0zZWY5LTQ2ODktODE0My03NmIxOTRlODU1MDkiXSwieG1zX3RjZHQiOjE2MTUzNzU2Mjl9.Y5rRF-vwImsUEaaZS4GcSc_PBTCxLvn7UZoxqOkljKHawMCxjExCqxU3BpM9l1jgBncI4rEOF5VD6htgzRXBnOJdtwxrEp5AB_WKOhisfK6jfgRmgL1Z-DbuKIAjnCmWCcQv1Pi0r6ltXW_8EU_OFKtX0xtKNwsDdRkWHUTp8D62Ogr-KtZAxul1NhKwqGUQUWlS1N7_Q8wO4hGslJ_cve8GYAjgvWWoyKsuJcV1xKa4z4EfRjXQ-fCxFMZ3Evqp4KQoITXD_0_gIFrRHTSyUVy1E4vg5_F_C-CLyHzWQL6ss80NeL0IvAcwLBz3I_jTV1QzsHbHSH2-kGbLj_-XNg',
          'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IkwxS2ZLRklfam5YYndXYzIyeFp4dzFzVUhIMCIsImtpZCI6IkwxS2ZLRklfam5YYndXYzIyeFp4dzFzVUhIMCJ9.eyJhdWQiOiJodHRwczovL2dyYXBoLndpbmRvd3MubmV0LyIsImlzcyI6Imh0dHBzOi8vc3RzLndpbmRvd3MubmV0LzJkNTBjYjI5LTVmN2ItNDhhNC04N2NlLWZlNzVhOTQxYWRiNi8iLCJpYXQiOjE3MTc0MzU4MzYsIm5iZiI6MTcxNzQzNTgzNiwiZXhwIjoxNzE3NDQwMzIxLCJhY3IiOiIxIiwiYWlvIjoiQVRRQXkvOFdBQUFBbFRkbmxMUnp5bkNoWHhhZTQzUVJuS0FUb0hCa2xObTdLcC96QmFvdm9CVXhPZG1uOW4yY01LSUVZYTVzYjdrRCIsImFtciI6WyJwd2QiXSwiYXBwaWQiOiIwNGIwNzc5NS04ZGRiLTQ2MWEtYmJlZS0wMmY5ZTFiZjdiNDYiLCJhcHBpZGFjciI6IjAiLCJpcGFkZHIiOiI1MS4yMTAuMS4yMzkiLCJuYW1lIjoiTWFyayBELiBXYWxkZW4iLCJvaWQiOiJmNjZlMTMzYy1iZDAxLTRiMGItYjNiNy03Y2Q5NDlmZDQ1ZjMiLCJwdWlkIjoiMTAwMzIwMDEyMEQ0Q0U0QiIsInJoIjoiMC5BWEFBS2N0UUxYdGZwRWlIenY1MXFVR3R0Z0lBQUFBQUFBQUF3QUFBQUFBQUFBREVBQ2MuIiwic2NwIjoiNjJlOTAzOTQtNjlmNS00MjM3LTkxOTAtMDEyMTc3MTQ1ZTEwIiwic3ViIjoiWmoxUC0zY05mYzNXd3pJdTRRS1lBVVhzZnVmM3JCTElnajhfSEJXeEtybyIsInRlbmFudF9yZWdpb25fc2NvcGUiOiJBUyIsInRpZCI6IjJkNTBjYjI5LTVmN2ItNDhhNC04N2NlLWZlNzVhOTQxYWRiNiIsInVuaXF1ZV9uYW1lIjoiTWFya0RXYWxkZW5AZGVmY29ycGhxLm9ubWljcm9zb2Z0LmNvbSIsInVwbiI6Ik1hcmtEV2FsZGVuQGRlZmNvcnBocS5vbm1pY3Jvc29mdC5jb20iLCJ1dGkiOiJERkNVdzZsQWdFNk05NDJDTjg3YUFBIiwidmVyIjoiMS4wIn0.HoazTDqkWLWHNH_kbKuttqJ_gY-zaeK3guaNh1qZFM8miX3CdTTxlxfQyeo1F0G1dCQjq188qAGFzBxjQcPKC7ywFF-od122eI_l2ckeZTI44BDo2Vy-XoAXTaFakgm5ol-hFfc5dfikmu6Kgp0EQaUVIOOdIzqKuElYnx1qqSAHanxhWS7m44ASewOTkjiipkLhss_jGoMWcqSXgL2YxCsCtcv5UOOkCsq-V7XZ7bCuqnyfZ_waRNskNe7GgM_CsHmxn2PqKMbqqIoGC7Lcv7vOGW9YxWZVfxuxKnVq5k-VyzaoInlx5bTLNlxr_Ssqki1CpQMJmue_nwyDCiCpnw',
          '',
          '',
          nil
        ],
        [
          'aaaaaaaa-1111-1111-aaaa-111111111133', 'AccessToken',
          'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IkwxS2ZLRklfam5YYndXYzIyeFp4dzFzVUhIMCIsImtpZCI6IkwxS2ZLRklfam5YYndXYzIyeFp4dzFzVUhIMCJ9.eyJhdWQiOiJodHRwczovL21hbmFnZW1lbnQuYXp1cmUuY29tLyIsImlzcyI6Imh0dHBzOi8vc3RzLndpbmRvd3MubmV0LzJkNTBjYjI5LTVmN2ItNDhhNC04N2NlLWZlNzVhOTQxYWRiNi8iLCJpYXQiOjE3MTc0MTg3ODMsIm5iZiI6MTcxNzQxODc4MywiZXhwIjoxNzE3NTA1NDgzLCJhaW8iOiJFMk5nWUZpVkVWbXg0SkowMU5XaWwwRnZEVHFpQVE9PSIsImFwcGlkIjoiMDY0YWFmNTctMzBhZi00MWYwLTg0MGEtMGUyMWVkMTQ5OTQ2IiwiYXBwaWRhY3IiOiIyIiwiaWRwIjoiaHR0cHM6Ly9zdHMud2luZG93cy5uZXQvMmQ1MGNiMjktNWY3Yi00OGE0LTg3Y2UtZmU3NWE5NDFhZGI2LyIsImlkdHlwIjoiYXBwIiwib2lkIjoiY2M2N2M5MGQtZDllOS00MGQyLWI1MTEtOWQ1MmQ2NzY4MmFiIiwicmgiOiIwLkFYQUFLY3RRTFh0ZnBFaUh6djUxcVVHdHRrWklmM2tBdXRkUHVrUGF3ZmoyTUJQRUFBQS4iLCJzdWIiOiJjYzY3YzkwZC1kOWU5LTQwZDItYjUxMS05ZDUyZDY3NjgyYWIiLCJ0aWQiOiIyZDUwY2IyOS01ZjdiLTQ4YTQtODdjZS1mZTc1YTk0MWFkYjYiLCJ1dGkiOiJrZDBkanNYQWIwSzZGdEZJMzNvekFBIiwidmVyIjoiMS4wIiwieG1zX21pcmlkIjoiL3N1YnNjcmlwdGlvbnMvYjQxMzgyNmYtMTA4ZC00MDQ5LThjMTEtZDUyZDVkMzg4NzY4L3Jlc291cmNlZ3JvdXBzL0VuZ2luZWVyaW5nL3Byb3ZpZGVycy9NaWNyb3NvZnQuV2ViL3NpdGVzL2RlZmNvcnBocWNhcmVlciIsInhtc190Y2R0IjoiMTYxNTM3NTYyOSJ9.fdLyjWihy0Q8QPAJj0p_CRMqgj0_N87x4u7flu3Hogw1OzdFe4yA7IfeO3_pwTqezPdY2aihBHhlyBs4uX-pK8c_3_n3kjLOnAcizRFzhHhO5-dS4p_izapje9Eqq5NvoR6-v05CIPp2k1hL4Kww4wSLUNRLid6olmSG8S7nyfoFNicdYGo0YNEOqqMq8SkQpaWpmwPnLMpkIp1oZNUiJSSHxFOjj3typkxSFKde4acsqU8LaTCL1quP6oxWmPf2GwDYmz8K5pspL9O2YB-jbId6m_0Fw2omA1QJSh2_lUvEm2LQYDUksFXjC4mov0O3UYa68SFuMHVosY-aMA7BNg',
          '',
          '',
          '',
          nil
        ]
      ])
    end
  end

  context '.process_profile_file' do
    it 'should return data on an azure profile content' do
      expect(subject.send(:process_profile_file, azure_profile)).to eql([['N/A(tenant level account)', 'example@example.onmicrosoft.com', 'AzureCloud'], ['Example', '11111111-1111-1111-1111-111111111111', 'AzureCloud']])
    end
  end

  context '.print_consolehost_history' do
    it 'returns [] on no hits' do
      expect(subject.send(:print_consolehost_history, 'test')).to eq([])
    end

    describe '' do
      [
        {
          input: "$creds = New-Object System.Management.Automation.PSCredential('example', $password)",
          output: ['Line 1 may contain sensitive information. Manual search recommended, keyword hit: System.Management.Automation.PSCredential']
        },
        {
          input: "$password = ConvertTo-SecureString 'example' -AsPlainText -Force",
          output: ['Line 1 may contain sensitive information. Manual search recommended, keyword hit: ConvertTo-SecureString']
        },
        {
          input: 'Connect-AzAccount -AccessToken $AccessToken -AccountId 11111111-1111-1111-1111-111111111111',
          output: ['Line 1 may contain sensitive information. Manual search recommended, keyword hit: Connect-AzAccount']
        },
        {
          input: '$server = New-PSSession -ComputerName 1.1.1.1 -Credential $creds',
          output: ['Line 1 may contain sensitive information. Manual search recommended, keyword hit: New-PSSession']
        },
        {
          input: %q|Set-AzVMExtension -ResourceGroupName "example" -ExtensionName "ExecCmd" -VMName "server" -Location "Example" -Publisher Microsoft.Compute -ExtensionType CustomScriptExtension -TypeHandlerVersion 1.8 -SettingString '{"commandToExecute":"powershell net users example example /add /Y; net localgroup administrators example /add"}'|,
          output: ['Line 1 may contain sensitive information. Manual search recommended, keyword hit: commandToExecute']
        },
        {
          input: 'Invoke-Command -Session $infradminsrv -ScriptBlock{hostname}',
          output: ['Line 1 may contain sensitive information. Manual search recommended, keyword hit: -ScriptBlock']
        },
      ].each do |test|
        it 'return Array with hits' do
          expect(subject.send(:print_consolehost_history, test[:input])).to eq(test[:output])
        end
      end
    end
  end
end
