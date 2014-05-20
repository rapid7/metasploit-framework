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

end