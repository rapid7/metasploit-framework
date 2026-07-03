# frozen_string_literal: true

require 'acceptance_spec_helper'

RSpec.describe 'LDAP modules' do
  include_context 'protocol_session_acceptance'

  tests = {
    ldap: {
      target: {
        session_module: 'auxiliary/scanner/ldap/ldap_login',
        type: 'LDAP',
        platforms: %i[linux osx windows],
        session_info_pattern: /LDAP #{Regexp.escape(ENV.fetch('LDAP_LDAPUsername', 'DEV-AD\Administrator'))} @ \d+\.\d+\.\d+\.\d+/,
        datastore: {
          global: {},
          module: {
            ldapusername: ENV.fetch('LDAP_LDAPUsername', 'DEV-AD\Administrator'),
            ldappassword: ENV.fetch('LDAP_LDAPPassword', 'admin123!'),
            rhost: ENV.fetch('LDAP_RHOST', '127.0.0.1'),
            rport: ENV.fetch('LDAP_RPORT', '389'),
            ssl: ENV.fetch('LDAP_SSL', 'false')
          }
        }
      },
      module_tests: [
        {
          name: 'auxiliary/gather/ldap_query',
          platforms: %i[linux osx windows],
          targets: [:session, :rhost],
          skipped: false,
          action: 'run_query_file',
          datastore: { QUERY_FILE_PATH: 'data/auxiliary/gather/ldap_query/ldap_queries_default.yaml' },
          lines: {
            all: {
              required: [
                /Loading queries from/,
                /ldap_queries_default.yaml.../,
                /Discovered base DN/,
                /Running ENUM_ACCOUNTS.../,
                /Running ENUM_USER_SPNS_KERBEROAST.../,
                /Running ENUM_USER_PASSWORD_NOT_REQUIRED.../,
              ]
            }
          }
        },
        {
          name: 'auxiliary/gather/ldap_query',
          platforms: %i[linux osx windows],
          targets: [:session, :rhost],
          skipped: false,
          action: 'enum_accounts',
          lines: {
            all: {
              required: [
                /Discovered base DN/,
                /Query returned 5 results/
              ]
            }
          }
        },
        {
          name: 'auxiliary/gather/ldap_passwords',
          platforms: %i[linux osx windows],
          targets: [:session, :rhost],
          skipped: false,
          lines: {
            all: {
              required: [
                /Searching base DN: DC=ldap,DC=example,DC=com/,
                /Checking if the target LDAP server is an Active Directory Domain Controller.../,
                /The target LDAP server is not an Active Directory Domain Controller./,
                /Credential found in ms-mcs-admpwd: Administrator:\[LAPSv1\]SuperSecretPassword!/,
                /Credential found in mslaps-password: Administrator:\[LAPSv2\]SuperSecretPassword!/,
                /Found [1-9]\d* entries and [1-9]\d* credentials in 'DC=ldap,DC=example,DC=com'./
              ]
            }
          }
        },
        {
          name: 'auxiliary/admin/ldap/shadow_credentials',
          platforms: %i[linux osx windows],
          targets: [:session, :rhost],
          skipped: false,
          datastore: { TARGET_USER: 'administrator' },
          lines: {
            all: {
              required: [
                /Discovered base DN: DC=ldap,DC=example,DC=com/,
                /The msDS-KeyCredentialLink field is empty./
              ]
            }
          }
        },
        {
          name: 'auxiliary/admin/ldap/rbcd',
          platforms: %i[linux osx windows],
          targets: [:session, :rhost],
          skipped: false,
          datastore: { DELEGATE_TO: 'administrator' },
          lines: {
            all: {
              required: [
                /The msDS-AllowedToActOnBehalfOfOtherIdentity field is empty./
              ]
            }
          }
        },
      ]
    }
  }

  run_protocol_session_tests(tests, features: %w[ldap_session_type])
end
