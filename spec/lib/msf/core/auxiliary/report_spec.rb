require 'spec_helper'
require 'msf/core/auxiliary/report'

describe Msf::Auxiliary::Report do
  include_context 'Msf::DBManager'
  let(:dummy_class) {
    Class.new do
      include Msf::Auxiliary::Report

      attr_accessor :framework
      def initialize(framework_instance)
        @framework = framework_instance
      end
    end
  }

  let(:session) { FactoryGirl.create(:mdm_session) }

  let(:task) { FactoryGirl.create(:mdm_task)}

  let(:user) { FactoryGirl.create(:mdm_user)}

  subject(:test_object) { dummy_class.new(framework) }

  context '#create_credential_origin_import' do
    it 'creates a Metasploit::Credential::Origin object' do
      opts = {
          filename: "test_import.xml",
          task_id: task.id
      }
      expect { test_object.create_credential_origin_import(opts)}.to change{Metasploit::Credential::Origin::Import.count}.by(1)
    end

    it 'should return nil if there is no database connection' do
      my_module = test_object
      expect(my_module.framework.db).to receive(:active).and_return(false)
      expect(my_module.create_credential_origin_import).to be_nil
    end

    context 'when called twice with the same options' do
      it 'does not create duplicate objects' do
        opts = {
            filename: "test_import.xml",
            task_id: task.id
        }
        test_object.create_credential_origin_import(opts)
        expect { test_object.create_credential_origin_import(opts)}.to_not change{Metasploit::Credential::Origin::Import.count}
      end
    end

    context 'when missing an option' do
      it 'throws a KeyError' do
        opts = {
          filename: "test_import.xml"
        }
        expect{ test_object.create_credential_origin_import(opts)}.to raise_error KeyError
      end
    end


  end

  context '#create_credential_origin_manual' do
    it 'creates a Metasploit::Credential::Origin object' do
      opts = {
        user_id: user.id
      }
      expect { test_object.create_credential_origin_manual(opts)}.to change{Metasploit::Credential::Origin::Manual.count}.by(1)
    end

    it 'should return nil if there is no database connection' do
      my_module = test_object
      expect(my_module.framework.db).to receive(:active).and_return(false)
      expect(my_module.create_credential_origin_manual).to be_nil
    end

    context 'when called twice with the same options' do
      it 'does not create duplicate objects' do
        opts = {
            user_id: user.id
        }
        test_object.create_credential_origin_manual(opts)
        expect { test_object.create_credential_origin_manual(opts)}.to_not change{Metasploit::Credential::Origin::Manual.count}
      end
    end

    context 'when missing an option' do
      it 'throws a KeyError' do
        opts = {}
        expect{ test_object.create_credential_origin_manual(opts)}.to raise_error KeyError
      end
    end
  end

  context '#create_credential_origin_service' do
    it 'creates a Metasploit::Credential::Origin object' do
      opts = {
        address: '192.168.172.3',
        port: 445,
        service_name: 'smb',
        protocol: 'tcp',
        module_fullname: 'auxiliary/scanner/smb/smb_login',
        workspace_id: framework.db.workspace.id,
        origin_type: :service
      }
      expect { test_object.create_credential_origin_service(opts)}.to change{Metasploit::Credential::Origin::Service.count}.by(1)
    end

    it 'should return nil if there is no database connection' do
      my_module = test_object
      expect(my_module.framework.db).to receive(:active).and_return(false)
      expect(my_module.create_credential_origin_service).to be_nil
    end

    context 'when there is a matching host record' do
      it 'creates a new host record' do
        opts = {
            address: '192.168.172.3',
            port: 445,
            service_name: 'smb',
            protocol: 'tcp',
            module_fullname: 'auxiliary/scanner/smb/smb_login',
            workspace_id: framework.db.workspace.id,
            origin_type: :service
        }
        FactoryGirl.create(:mdm_host, address: opts[:address], workspace_id: opts[:workspace_id])
        expect { test_object.create_credential_origin_service(opts)}.to_not change{Mdm::Host.count}
      end
    end

    context 'when there is not a matching host record' do
      it 'uses the existing host record' do
        opts = {
            address: '192.168.172.3',
            port: 445,
            service_name: 'smb',
            protocol: 'tcp',
            module_fullname: 'auxiliary/scanner/smb/smb_login',
            workspace_id: framework.db.workspace.id,
            origin_type: :service
        }
        expect { test_object.create_credential_origin_service(opts)}.to change{Metasploit::Credential::Origin::Service.count}.by(1)
      end
    end

    context 'when there is a matching service record' do
      it 'uses the existing service record' do
        opts = {
            address: '192.168.172.3',
            port: 445,
            service_name: 'smb',
            protocol: 'tcp',
            module_fullname: 'auxiliary/scanner/smb/smb_login',
            workspace_id: framework.db.workspace.id,
            origin_type: :service
        }
        host = FactoryGirl.create(:mdm_host, address: opts[:address], workspace_id: opts[:workspace_id])
        FactoryGirl.create(:mdm_service, host_id: host.id, port: opts[:port], proto: opts[:protocol])
        expect { test_object.create_credential_origin_service(opts)}.to_not change{Mdm::Service.count}
      end
    end

    context 'when there is no matching service record' do
      it 'creates a new service record' do
        opts = {
            address: '192.168.172.3',
            port: 445,
            service_name: 'smb',
            protocol: 'tcp',
            module_fullname: 'auxiliary/scanner/smb/smb_login',
            workspace_id: framework.db.workspace.id,
            origin_type: :service
        }
        expect { test_object.create_credential_origin_service(opts)}.to change{Mdm::Service.count}.by(1)
      end
    end

    context 'when called twice with the same options' do
      it 'does not create duplicate objects' do
        opts = {
            address: '192.168.172.3',
            port: 445,
            service_name: 'smb',
            protocol: 'tcp',
            module_fullname: 'auxiliary/scanner/smb/smb_login',
            workspace_id: framework.db.workspace.id,
            origin_type: :service
        }
        test_object.create_credential_origin_service(opts)
        expect { test_object.create_credential_origin_service(opts)}.to_not change{Metasploit::Credential::Origin::Service.count}
      end
    end

    context 'when missing an option' do
      it 'throws a KeyError' do
        opts = {}
        expect{ test_object.create_credential_origin_service(opts)}.to raise_error KeyError
      end
    end
  end

  context '#create_credential_origin_session' do
    it 'creates a Metasploit::Credential::Origin object' do
      opts = {
          post_reference_name: 'windows/gather/hashdump',
          session_id: session.id
      }
      expect { test_object.create_credential_origin_session(opts)}.to change{Metasploit::Credential::Origin::Session.count}.by(1)
    end

    it 'should return nil if there is no database connection' do
      my_module = test_object
      expect(my_module.framework.db).to receive(:active).and_return(false)
      expect(my_module.create_credential_origin_session).to be_nil
    end

    context 'when called twice with the same options' do
      it 'does not create duplicate objects' do
        opts = {
            post_reference_name: 'windows/gather/hashdump',
            session_id: session.id
        }
        test_object.create_credential_origin_session(opts)
        expect { test_object.create_credential_origin_session(opts)}.to_not change{Metasploit::Credential::Origin::Session.count}
      end
    end

    context 'when missing an option' do
      it 'throws a KeyError' do
        opts = {}
        expect{ test_object.create_credential_origin_session(opts)}.to raise_error KeyError
      end
    end
  end

  context '#create_credential_origin' do
    it 'should return nil if there is no database connection' do
      my_module = test_object
      expect(my_module.framework.db).to receive(:active).and_return(false)
      expect(my_module.create_credential_origin).to be_nil
    end

    it 'calls the correct method to create Origin::Import records' do
      opts = {
          filename: "test_import.xml",
          origin_type: :import,
          task_id: task.id
      }
      my_module = test_object
      expect(my_module).to receive(:create_credential_origin_import)
      my_module.create_credential_origin(opts)
    end

    it 'calls the correct method to create Origin::Manual records' do
      opts = {
          origin_type: :manual,
          user_id: user.id
      }
      my_module = test_object
      expect(my_module).to receive(:create_credential_origin_manual)
      my_module.create_credential_origin(opts)
    end

    it 'calls the correct method to create Origin::Service records' do
      opts = {
        address: '192.168.172.3',
        port: 445,
        service_name: 'smb',
        protocol: 'tcp',
        module_fullname: 'auxiliary/scanner/smb/smb_login',
        workspace_id: framework.db.workspace.id,
        origin_type: :service
      }
      my_module = test_object
      expect(my_module).to receive(:create_credential_origin_service)
      my_module.create_credential_origin(opts)
    end

    it 'calls the correct method to create Origin::Session records' do
      opts = {
          origin_type: :session,
          post_reference_name: 'windows/gather/hashdump',
          session_id: session.id
      }
      my_module = test_object
      expect(my_module).to receive(:create_credential_origin_session)
      my_module.create_credential_origin(opts)
    end

    it 'raises an exception if there is no origin type' do
      opts = {
          post_reference_name: 'windows/gather/hashdump',
          session_id: session.id
      }
      expect{test_object.create_credential_origin(opts)}.to raise_error ArgumentError, "Unknown Origin Type "
    end

    it 'raises an exception if given an invalid origin type' do
      opts = {
          origin_type: 'aaaaa',
          post_reference_name: 'windows/gather/hashdump',
          session_id: session.id
      }
      expect{test_object.create_credential_origin(opts)}.to raise_error ArgumentError, "Unknown Origin Type aaaaa"
    end
  end

  context '#create_credential_realm' do
    it 'creates a Metasploit::Credential::Realm object' do
      opts = {
          realm_key: 'Active Directory Domain',
          realm_value: 'contosso'
      }
      expect { test_object.create_credential_realm(opts)}.to change{Metasploit::Credential::Realm.count}.by(1)
    end

    it 'should return nil if there is no database connection' do
      my_module = test_object
      expect(my_module.framework.db).to receive(:active).and_return(false)
      expect(my_module.create_credential_realm).to be_nil
    end

    context 'when called twice with the same options' do
      it 'does not create duplicate objects' do
        opts = {
            realm_key: 'Active Directory Domain',
            realm_value: 'contosso'
        }
        test_object.create_credential_realm(opts)
        expect { test_object.create_credential_realm(opts)}.to_not change{Metasploit::Credential::Realm.count}
      end
    end

    context 'when missing an option' do
      it 'throws a KeyError' do
        opts = {}
        expect{ test_object.create_credential_origin_manual(opts)}.to raise_error KeyError
      end
    end
  end

  context '#create_credential_private' do
    it 'should return nil if there is no database connection' do
      my_module = test_object
      expect(my_module.framework.db).to receive(:active).and_return(false)
      expect(my_module.create_credential_private).to be_nil
    end

    context 'when missing an option' do
      it 'throws a KeyError' do
        opts = {}
        expect{ test_object.create_credential_private(opts)}.to raise_error KeyError
      end
    end

    context 'when :private_type is password' do
      it 'creates a Metasploit::Credential::Password' do
        opts = {
          private_data: 'password1',
          private_type: :password
        }
        expect{ test_object.create_credential_private(opts) }.to change{Metasploit::Credential::Password.count}.by(1)
      end
    end

    context 'when :private_type is sshkey' do
      it 'creates a Metasploit::Credential::SSHKey' do
        opts = {
            private_data: OpenSSL::PKey::RSA.generate(2048).to_s,
            private_type: :ssh_key
        }
        expect{ test_object.create_credential_private(opts) }.to change{Metasploit::Credential::SSHKey.count}.by(1)
      end
    end

    context 'when :private_type is ntlmhash' do
      it 'creates a Metasploit::Credential::NTLMHash' do
        opts = {
            private_data: Metasploit::Credential::NTLMHash.data_from_password_data('password1'),
            private_type: :ntlm_hash
        }
        expect{ test_object.create_credential_private(opts) }.to change{Metasploit::Credential::NTLMHash.count}.by(1)
      end
    end

    context 'when :private_type is nonreplayable_hash' do
      it 'creates a Metasploit::Credential::NonreplayableHash' do
        opts = {
            private_data: '10b222970537b97919db36ec757370d2',
            private_type: :nonreplayable_hash
        }
        expect{ test_object.create_credential_private(opts) }.to change{Metasploit::Credential::NonreplayableHash.count}.by(1)
      end
    end
  end

  context '#create_credential_core' do
    let(:origin)  { FactoryGirl.create(:metasploit_credential_origin_service) }
    let(:public)  { FactoryGirl.create(:metasploit_credential_public)}
    let(:private) { FactoryGirl.create(:metasploit_credential_password)}
    let(:realm)   { FactoryGirl.create(:metasploit_credential_realm)}

    it 'raises a KeyError if any required option is missing' do
      opts = {}
      expect{ test_object.create_credential_core(opts)}.to raise_error KeyError
    end

    it 'returns nil if there is no active database connection' do
      my_module = test_object
      expect(my_module.framework.db).to receive(:active).and_return(false)
      expect(my_module.create_credential_core).to be_nil
    end

    it 'creates a Metasploit::Credential::Core' do
      opts = {
        origin: origin,
        public: public,
        private: private,
        realm: realm,
        workspace_id: origin.service.host.workspace_id
      }
      expect{test_object.create_credential_core(opts)}.to change{Metasploit::Credential::Core.count}.by(1)
    end


  end

end