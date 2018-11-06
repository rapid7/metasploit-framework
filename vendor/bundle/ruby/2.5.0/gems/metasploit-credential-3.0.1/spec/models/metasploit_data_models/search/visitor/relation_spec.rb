RSpec.describe MetasploitDataModels::Search::Visitor::Relation, type: :model do
  subject(:visitor) {
    described_class.new(
        query: query
    )
  }

  let(:query) {
    Metasploit::Model::Search::Query.new(
        formatted: formatted,
        klass: klass
    )
  }

  context '#visit' do
    subject(:visit) {
      visitor.visit
    }

    context 'MetasploitDataModels::Search::Visitor::Relation#query Metasploit::Model::Search::Query#klass' do
      context 'with Metasploit::Credential::Core' do


        #
        # Shared Examples
        #

        shared_examples 'Metasploit::Credential::Private' do |options={}|
          options.assert_valid_keys(:name, :factory)

          subclass_factory = options.fetch(:factory)
          subclass_name = options.fetch(:name)

          context subclass_name do
            let(:private_factory) {
              subclass_factory
            }

            it_should_behave_like 'MetasploitDataModels::Search::Visitor::Relation#visit matching record',
                                  association: :private,
                                  attribute: :data

            context 'with all operators' do
              let(:formatted) {
                %Q{
                  logins.access_level:"#{matching_login_access_level}"
                  logins.status:"#{matching_login_status}"
                  private.data:"#{matching_private_data}"
                  public.username:"#{matching_public_username}"
                  realm.key:"#{matching_realm_key}"
                  realm.value:"#{matching_realm_value}"
                }
              }

              it 'finds only matching record' do
                expect(visit).to match_array([matching_record])
              end
            end
          end
        end

        #
        # lets
        #

        let(:klass) {
          Metasploit::Credential::Core
        }

        let(:matching_login_access_level) {
          'Administrator'
        }

        let(:matching_login_status) {
          Metasploit::Model::Login::Status::LOCKED_OUT
        }

        let(:matching_private) {
          FactoryBot.create(
              private_factory,
              matching_private_attributes
          )
        }

        let(:matching_private_attributes) {
          {}
        }

        let(:matching_private_data) {
          matching_private.data
        }

        let(:matching_public) {
          FactoryBot.create(
              :metasploit_credential_username,
              username: matching_public_username
          )
        }

        let(:matching_public_username) {
          'root'
        }

        let(:matching_realm) {
          FactoryBot.create(
              :metasploit_credential_realm,
              key: matching_realm_key,
              value: matching_realm_value
          )
        }

        let(:matching_realm_key) {
          Metasploit::Model::Realm::Key::POSTGRESQL_DATABASE
        }

        let(:matching_realm_value) {
          'postgres'
        }

        let(:non_matching_login_access_level) {
          'normal'
        }

        let(:non_matching_login_status) {
          Metasploit::Model::Login::Status::SUCCESSFUL
        }

        let(:non_matching_private) {
          FactoryBot.create(
              private_factory,
              non_matching_private_attributes
          )
        }

        let(:non_matching_private_attributes) {
          {}
        }

        let(:non_matching_public) {
          FactoryBot.create(
              :metasploit_credential_username,
              username: non_matching_public_username
          )
        }

        let(:non_matching_public_username) {
          'guest'
        }

        let(:non_matching_realm) {
          FactoryBot.create(
              :metasploit_credential_realm,
              key: non_matching_realm_key,
              value: non_matching_realm_value
          )
        }

        let(:non_matching_realm_key) {
          Metasploit::Model::Realm::Key::ACTIVE_DIRECTORY_DOMAIN
        }

        let(:non_matching_realm_value) {
          'DOMAIN'
        }

        let(:private_factory) {
          [
              :metasploit_credential_nonreplayable_hash,
              :metasploit_credential_ntlm_hash,
              :metasploit_credential_password,
              :metasploit_credential_ssh_key
          ].sample
        }

        #
        # let!s
        #

        let!(:matching_login) {
          FactoryBot.create(
              :metasploit_credential_login,
              access_level: matching_login_access_level,
              core: matching_record,
              status: matching_login_status
          )
        }

        let!(:matching_record) {
          FactoryBot.create(
              :metasploit_credential_core,
              private: matching_private,
              public: matching_public,
              realm: matching_realm
          )
        }

        let!(:non_matching_login) {
          FactoryBot.create(
              :metasploit_credential_login,
              access_level: non_matching_login_access_level,
              core: non_matching_record,
              status: non_matching_login_status
          )
        }

        let!(:non_matching_record) {
          FactoryBot.create(
              :metasploit_credential_core,
              private: non_matching_private,
              public: non_matching_public,
              realm: non_matching_realm
          )
        }

        it_should_behave_like 'MetasploitDataModels::Search::Visitor::Relation#visit matching record',
                              association: :logins,
                              attribute: :access_level

        it_should_behave_like 'MetasploitDataModels::Search::Visitor::Relation#visit matching record',
                              association: :logins,
                              attribute: :status

        it_should_behave_like 'MetasploitDataModels::Search::Visitor::Relation#visit matching record',
                              association: :public,
                              attribute: :username

        it_should_behave_like 'MetasploitDataModels::Search::Visitor::Relation#visit matching record',
                              association: :realm,
                              attribute: :key

        it_should_behave_like 'MetasploitDataModels::Search::Visitor::Relation#visit matching record',
                              association: :realm,
                              attribute: :value

        context 'wth Metasploit::Credential::PasswordHash' do

          #
          # lets
          #

          let(:matching_private_attributes) {
            {
                password_data: '123456789'
            }
          }

          let(:non_matching_private_attributes) {
            {
                password_data: 'password'
            }
          }

          it_should_behave_like 'Metasploit::Credential::Private',
                                factory: :metasploit_credential_nonreplayable_hash,
                                name: 'Metasploit::Credential::NonreplayableHash'


          it_should_behave_like 'Metasploit::Credential::Private',
                                factory: :metasploit_credential_ntlm_hash,
                                name: 'Metasploit::Credential::NTLMHash'
        end

        it_should_behave_like 'Metasploit::Credential::Private',
                              factory: :metasploit_credential_password,
                              name: 'Metasploit::Credential::Password' do
          let(:matching_attributes) {
            {
                data: '123456789'
            }
          }

          let(:non_matching_attributes) {
            {
                # needs to not be a substring alias of matching_attributes[:password_data]
                data: 'password'
            }
          }
        end

        it_should_behave_like 'Metasploit::Credential::Private',
                              factory: :metasploit_credential_ssh_key,
                              name: 'Metasploit::Credental::SSHKey'
      end

      context 'with Metasploit::Credential::Login' do

        include_context 'Rex::Text'

        #
        # lets
        #

        let(:klass) {
          Metasploit::Credential::Login
        }

        let(:matching_access_level) {
          'admin'
        }

        let(:matching_credential_core) {
          FactoryBot.create(
              :metasploit_credential_core
          )
        }

        let(:matching_host) {
          FactoryBot.create(
              :mdm_host,
              address: matching_host_address,
              name: matching_host_name,
              os_flavor: matching_host_os_flavor,
              os_name: matching_host_os_name,
              os_sp: matching_host_os_sp,
              workspace: matching_credential_core.workspace
          )
        }

        let(:matching_host_address) {
          '1.2.3.4'
        }

        let(:matching_host_name) {
          'mdm_host_name_a'
        }

        let(:matching_host_os_flavor) {
          'mdm_host_os_flavor_a'
        }

        let(:matching_host_os_name) {
          'mdm_host_os_name_a'
        }

        let(:matching_host_os_sp) {
          'mdm_host_os_sp_a'
        }

        let(:matching_service) {
          FactoryBot.create(
              :mdm_service,
              host: matching_host,
              info: matching_service_info,
              name: matching_service_name,
              port: matching_service_port,
              proto: matching_service_proto
          )
        }

        let(:matching_service_info) {
          'mdm_service_info_a'
        }

        let(:matching_service_name) {
          'mdm_service_name_a'
        }

        let(:matching_service_port) {
          1
        }

        let(:matching_service_proto) {
          'tcp'
        }

        let(:matching_status) {
          matching_record.status
        }

        let(:non_matching_access_level) {
          'normal'
        }

        let(:non_matching_credential_core) {
          FactoryBot.create(
              :metasploit_credential_core
          )
        }

        let(:non_matching_host) {
          FactoryBot.create(
              :mdm_host,
              address: non_matching_host_address,
              name: non_matching_host_name,
              os_flavor: non_matching_host_os_flavor,
              os_name: non_matching_host_os_name,
              os_sp: non_matching_host_os_sp,
              workspace: non_matching_credential_core.workspace
          )
        }

        let(:non_matching_host_address) {
          '5.6.7.8'
        }

        let(:non_matching_host_name) {
          'mdm_host_name_b'
        }

        let(:non_matching_host_os_flavor) {
          'mdm_host_os_flavor_b'
        }

        let(:non_matching_host_os_name) {
          'mdm_host_os_name_b'
        }

        let(:non_matching_host_os_sp) {
          'mdm_host_os_sp_b'
        }

        let(:non_matching_service) {
          FactoryBot.create(
              :mdm_service,
              host: non_matching_host,
              info: non_matching_service_info,
              name: non_matching_service_name,
              port: non_matching_service_port,
              proto: non_matching_service_proto
          )
        }

        let(:non_matching_service_info) {
          'mdm_service_info_b'
        }

        let(:non_matching_service_name) {
          'mdm_service_name_b'
        }

        let(:non_matching_service_port) {
          2
        }

        let(:non_matching_service_proto) {
          'udp'
        }

        #
        # let!s
        #

        let!(:matching_record) {
          FactoryBot.create(
              :metasploit_credential_login,
              access_level: matching_access_level,
              core: matching_credential_core,
              service: matching_service
          )
        }

        let!(:non_matching_record) {
          FactoryBot.create(
              :metasploit_credential_login,
              access_level: non_matching_access_level,
              core: non_matching_credential_core,
              service: non_matching_service
          )
        }

        it_should_behave_like 'MetasploitDataModels::Search::Visitor::Relation#visit matching record',
                              attribute: :access_level

        it_should_behave_like 'MetasploitDataModels::Search::Visitor::Relation#visit matching record',
                              attribute: :status


        context 'with host.address operator' do
          let(:formatted) do
            "host.address:#{formatted_address}"
          end

          context 'with CIDR' do
            let(:formatted_address) {
              '1.3.4.5/8'
            }

            it 'should find only matching record' do
              expect(visit).to match_array([matching_record])
            end
          end

          context 'with Range' do
            let(:formatted_address) {
              '1.1.1.1-5.6.7.7'
            }

            it 'should find only matching record' do
              expect(visit).to match_array([matching_record])
            end
          end

          context 'with single' do
            let(:formatted_address) {
              '1.2.3.4'
            }

            it 'should find only matching record' do
              expect(visit).to match_array([matching_record])
            end
          end
            end

        context 'with host.os' do
          let(:matching_host_os_flavor) {
            'XP'
          }

          let(:matching_host_os_name) {
            'Microsoft Windows'
          }

          let(:matching_host_os_sp) {
            'SP1'
          }

          context 'with a combination of Mdm::Host#os_name and Mdm:Host#os_sp' do
            let(:formatted) {
              %Q{host.os:"win xp"}
            }

            it 'finds matching record' do
              expect(visit).to match_array [matching_record]
            end
          end

          context 'with a combination of Mdm::Host#os_flavor and Mdm::Host#os_sp' do
            let(:formatted) {
              %Q{host.os:"xp sp1"}
            }

            it 'finds matching record' do
              expect(visit).to match_array [matching_record]
            end
          end

          context 'with multiple records matching one word' do
            let(:formatted) {
              %Q{host.os:"win xp"}
            }

            let(:non_matching_host_os_name) {
              'Microsoft Windows'
            }

            it 'finds only matching record by other words refining search' do
              expect(visit).to match_array [matching_record]
            end
          end
        end

        it_should_behave_like 'MetasploitDataModels::Search::Visitor::Relation#visit matching record',
                              association: :host,
                              attribute: :name

        it_should_behave_like 'MetasploitDataModels::Search::Visitor::Relation#visit matching record',
                              association: :host,
                              attribute: :os_flavor

        it_should_behave_like 'MetasploitDataModels::Search::Visitor::Relation#visit matching record',
                              association: :host,
                              attribute: :os_name

         it_should_behave_like 'MetasploitDataModels::Search::Visitor::Relation#visit matching record',
                              association: :host,
                              attribute: :os_sp

        it_should_behave_like 'MetasploitDataModels::Search::Visitor::Relation#visit matching record',
                              association: :service,
                              attribute: :info

        it_should_behave_like 'MetasploitDataModels::Search::Visitor::Relation#visit matching record',
                              association: :service,
                              attribute: :name

        it_should_behave_like 'MetasploitDataModels::Search::Visitor::Relation#visit matching record',
                              association: :service,
                              attribute: :proto

        context 'with all operators' do
          let(:formatted) {
            %Q{
              access_level:"#{matching_access_level}"
              status:"#{matching_status}"
              host.address:1.3.4.5/8
              host.address:1.1.1.1-5.6.7.7
              host.address:1.2.3.4
              host.name:#{matching_host_name}
              host.os:"#{matching_host_os_name} #{matching_host_os_flavor} #{matching_host_os_sp}"
              host.os_flavor:#{matching_host_os_flavor}
              host.os_name:#{matching_host_os_name}
              host.os_sp:#{matching_host_os_sp}
              service.info:#{matching_service_info}
              service.name:#{matching_service_name}
              service.port:#{matching_service_port}
              service.proto:#{matching_service_proto}
            }
          }

          it 'returns only matching record' do
            expect(visit).to match_array([matching_record])
          end
        end
      end

      context 'with Metasploit::Credential::Private' do
        #
        # lets
        #

        let(:klass) {
          Metasploit::Credential::Private
        }

        context 'Metasploit::Credential::Private#data' do
          let(:matching_attributes) {
            {}
          }

          let(:non_matching_attributes) {
            {}
          }


          #
          # let!s
          #

          let!(:matching_record) {
            FactoryBot.create(
                factory,
                matching_attributes
            )
          }

          let!(:non_matching_record) {
            FactoryBot.create(
                factory,
                non_matching_attributes
            )
          }

          context 'wth Metasploit::Credential::PasswordHash subclass' do
            let(:matching_attributes) {
              {
                  password_data: '123456789'
              }
            }

            let(:non_matching_attributes) {
              {
                  password_data: 'password'
              }
            }

            context 'Metasploit::Credential::NonreplayableHash' do
              let(:factory) {
                :metasploit_credential_nonreplayable_hash
              }

              it_should_behave_like 'MetasploitDataModels::Search::Visitor::Relation#visit matching record',
                                    attribute: :data
            end

            context 'Metasploit::Credential::NTLMHash' do
              let(:factory) {
                :metasploit_credential_ntlm_hash
              }

              it_should_behave_like 'MetasploitDataModels::Search::Visitor::Relation#visit matching record',
                                    attribute: :data
            end
          end

          context 'with Metasploit::Credential::Password' do
            let(:factory) {
              :metasploit_credential_password
            }

            let(:matching_attributes) {
              {
                  data: '123456789'
              }
            }

            let(:non_matching_attributes) {
              {
                  # needs to not be a substring alias of matching_attributes[:password_data]
                  data: 'password'
              }
            }

            it_should_behave_like 'MetasploitDataModels::Search::Visitor::Relation#visit matching record',
                                  attribute: :data
          end

          context 'with Metasploit::Credential::SSHKey' do
            #
            # lets
            #

            let(:factory) {
              :metasploit_credential_ssh_key
            }

            it_should_behave_like 'MetasploitDataModels::Search::Visitor::Relation#visit matching record',
                                  attribute: :data
          end
        end

        context 'Metasploit::Credential::Private#type' do
          #
          # lets
          #

          let(:matching_record) {
            metasploit_credential_private_by_class.fetch(matching_class)
          }

          let(:metasploit_private_factories) {
            [
                :metasploit_credential_nonreplayable_hash,
                :metasploit_credential_ntlm_hash,
                :metasploit_credential_password,
                :metasploit_credential_ssh_key
            ]
          }

          #
          # let!s
          #

          let!(:metasploit_credential_private_by_class) {
            metasploit_private_factories.each_with_object({}) { |factory, instance_by_class|
              instance = FactoryBot.create(factory)
              instance_by_class[instance.class] = instance
            }
          }

          it_should_behave_like 'Metasploit::Credential::Search::Operation::Type',
                                matching_class: Metasploit::Credential::NonreplayableHash

          it_should_behave_like 'Metasploit::Credential::Search::Operation::Type',
                                matching_class: Metasploit::Credential::NTLMHash

          it_should_behave_like 'Metasploit::Credential::Search::Operation::Type',
                                matching_class: Metasploit::Credential::Password

          it_should_behave_like 'Metasploit::Credential::Search::Operation::Type',
                                matching_class: Metasploit::Credential::SSHKey
        end

        context 'with all operators' do
          #
          # shared examples
          #

          shared_examples_for 'matching class' do |matching_class|
            context "with #{matching_class}" do
              let(:matching_class) {
                matching_class
              }

              context 'with Class#name' do
                let(:matching_type) {
                  matching_class.name
                }

                it 'should find only matching record' do
                  expect(visit).to match_array([matching_record])
                end
              end

              context 'with Class#model_name.human' do
                let(:matching_type) {
                  matching_class.model_name.human
                }

                it 'should find only matching record' do
                  expect(visit).to match_array([matching_record])
                end
              end
            end
          end

          #
          # lets
          #

          let(:formatted) {
            %Q{data:"#{matching_data}" type:"#{matching_type}"}
          }

          let(:metasploit_credential_privates_by_class) {
            {
                Metasploit::Credential::NonreplayableHash => FactoryBot.create_list(
                    :metasploit_credential_nonreplayable_hash,
                    2
                ),
                Metasploit::Credential::NTLMHash => FactoryBot.create_list(
                    :metasploit_credential_ntlm_hash,
                    2
                ),
                Metasploit::Credential::Password => [
                    FactoryBot.create(
                        :metasploit_credential_password,
                        data: 'alices_password'
                    ),
                    FactoryBot.create(
                        :metasploit_credential_password,
                        data: 'bobs_password'
                    )
                ],
                Metasploit::Credential::SSHKey => FactoryBot.create_list(
                    :metasploit_credential_ssh_key,
                    2
                )
            }
          }

          let(:matching_class_records) {
            metasploit_credential_privates_by_class.fetch(matching_class)
          }

          let(:matching_data) {
            matching_record.data
          }

          let(:matching_record) {
            matching_class_records.sample
          }

          it_should_behave_like 'matching class', Metasploit::Credential::NonreplayableHash
          it_should_behave_like 'matching class', Metasploit::Credential::NTLMHash
        end
      end

      context 'with Metasploit::Credential::Public' do
        let(:klass) {
          Metasploit::Credential::Public
        }

        let(:matching_username) {
          'alice'
        }

        let(:non_matching_username) {
          # must not LIKE match matching_username
          'bob'
        }

        #
        # let!s
        #

        let!(:matching_record) {
          FactoryBot.create(
              :metasploit_credential_username,
              username: matching_username
          )
        }

        let!(:non_matching_record) {
          FactoryBot.create(
              :metasploit_credential_username,
              username: non_matching_username
          )
        }

        it_should_behave_like 'MetasploitDataModels::Search::Visitor::Relation#visit matching record',
                              attribute: :username
      end

      context 'with Metasploit::Credential::Realm' do
        #
        # lets
        #

        let(:klass) {
          Metasploit::Credential::Realm
        }

        let(:matching_key) {
          matching_record.key
        }

        let(:matching_value) {
          'matching_value'
        }

        let(:non_matching_value) {
          'other_value'
        }

        #
        # let!s
        #

        let!(:matching_record) {
          FactoryBot.create(
              :metasploit_credential_realm,
              value: matching_value
          )
        }

        let!(:non_matching_record) {
          FactoryBot.create(
              :metasploit_credential_realm,
              value: non_matching_value
          )
        }

        it_should_behave_like 'MetasploitDataModels::Search::Visitor::Relation#visit matching record',
                              attribute: :key

        it_should_behave_like 'MetasploitDataModels::Search::Visitor::Relation#visit matching record',
                              attribute: :value

        context 'with all operators' do
          let(:formatted) {
            %Q{key:"#{matching_key}" value:"#{matching_value}"}
          }

          it 'finds only the matching record' do
            expect(visit).to match_array([matching_record])
          end
        end
      end
    end
  end
end