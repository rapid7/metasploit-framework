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

end