RSpec.describe Mdm::Cred, type: :model do
  it_should_behave_like 'Metasploit::Concern.run'

  context "Associations" do
    it { is_expected.to have_many(:task_creds).class_name('Mdm::TaskCred').dependent(:destroy) }
    it { is_expected.to have_many(:tasks).class_name('Mdm::Task').through(:task_creds) }
    it { is_expected.to belong_to(:service).class_name('Mdm::Service') }
  end

  context 'database' do
    context 'timestamps' do
      it { is_expected.to have_db_column(:created_at).of_type(:datetime) }
      it { is_expected.to have_db_column(:updated_at).of_type(:datetime) }
    end

    context 'columns' do
      it { is_expected.to have_db_column(:service_id).of_type(:integer).with_options(:null => false) }
      it { is_expected.to have_db_column(:user).of_type(:string) }
      it { is_expected.to have_db_column(:pass).of_type(:string) }
      it { is_expected.to have_db_column(:active).of_type(:boolean).with_options(:default => true) }
      it { is_expected.to have_db_column(:proof).of_type(:string) }
      it { is_expected.to have_db_column(:ptype).of_type(:string) }
      it { is_expected.to have_db_column(:source_id).of_type(:integer) }
      it { is_expected.to have_db_column(:source_type).of_type(:string) }
    end
  end

  context '#destroy' do
    it 'should successfully destroy the object and all dependent objects' do
      cred = FactoryBot.create(:mdm_cred)
      task_cred = FactoryBot.create(:mdm_task_cred, :cred => cred)
      expect {
        cred.destroy
      }.to_not raise_error
      expect {
        cred.reload
      }.to raise_error(ActiveRecord::RecordNotFound)
      expect {
        task_cred.reload
      }.to raise_error(ActiveRecord::RecordNotFound)
    end
  end

  context 'callbacks' do
    context 'after_create' do
      it 'should increment cred_count on the host' do
        host = FactoryBot.create(:mdm_host)
        svc = FactoryBot.create(:mdm_service, :host => host)
        expect {
          FactoryBot.create(:mdm_cred, :service => svc)
        }.to change{ Mdm::Host.find(host.id).cred_count}.by(1)
      end
    end

    context 'after_destroy' do
      it 'should decrement cred_count on the host' do
        host = FactoryBot.create(:mdm_host)
        svc = FactoryBot.create(:mdm_service, :host => host)
        cred =FactoryBot.create(:mdm_cred, :service => svc)
        expect {
          cred.destroy
        }.to change{ Mdm::Host.find(host.id).cred_count}.by(-1)
      end
    end
  end

  context 'constants' do
    it 'should define the key_id regex' do
      expect(described_class::KEY_ID_REGEX).to eq(/([0-9a-fA-F:]{47})/)
    end

    it 'should define ptypes to humanize' do
      expect(described_class::PTYPES).to eq(
                                             {
                                                 'read/write password' => 'password_rw',
                                                 'read-only password' => 'password_ro',
                                                 'SMB hash' => 'smb_hash',
                                                 'SSH private key' => 'ssh_key',
                                                 'SSH public key' => 'ssh_pubkey'
                                             }
                                         )
    end
  end

  context 'methods' do
    let(:host) {
      FactoryBot.create(
          :mdm_host,
          workspace: workspace
      )
    }

    let(:other_service) {
      FactoryBot.create(
          :mdm_service,
          host: host
      )
    }

    let(:service) {
      FactoryBot.create(
          :mdm_service,
          host: host
      )
    }

    let(:ssh_key) {
      FactoryBot.create(
          :mdm_cred,
          pass: '/path/to/keyfile',
          proof: "KEY=57:c3:11:5d:77:c5:63:90:33:2d:c5:c4:99:78:62:7a",
          ptype: 'ssh_key',
          service: service,
          user: 'msfadmin'
      )
    }

    let(:ssh_pubkey) {
      FactoryBot.create(
          :mdm_cred,
          pass: '/path/to/keyfile',
          proof: "KEY=57:c3:11:5d:77:c5:63:90:33:2d:c5:c4:99:78:62:7a",
          ptype: 'ssh_pubkey',
          service: service,
          user: 'msfadmin'
      )
    }

    let(:workspace) {
      FactoryBot.create(:mdm_workspace)
    }

    context '#ptype_human' do
      it "should return 'read/write password' for 'password_rw'" do
        cred = FactoryBot.build(:mdm_cred, :user => 'msfadmin', :pass => 'msfadmin', :ptype => 'password_rw')
        expect(cred.ptype_human).to eq('read/write password')
      end

      it "should return 'read-only password' for 'password_ro'" do
        cred = FactoryBot.build(:mdm_cred, :user => 'msfadmin', :pass => 'msfadmin', :ptype => 'password_ro')
        expect(cred.ptype_human).to eq('read-only password')
      end

      it "should return 'SMB Hash' for 'smb_hash'" do
        cred = FactoryBot.build(:mdm_cred, :user => 'msfadmin', :pass => 'msfadmin', :ptype => 'smb_hash')
        expect(cred.ptype_human).to eq('SMB hash')
      end

      it "should return 'SSH private key' for 'ssh_key'" do
        cred = FactoryBot.build(:mdm_cred, :user => 'msfadmin', :pass => 'msfadmin', :ptype => 'ssh_key')
        expect(cred.ptype_human).to eq('SSH private key')
      end

      it "should return 'SSH public key' for 'ssh_pubkey'" do
        cred = FactoryBot.build(:mdm_cred, :user => 'msfadmin', :pass => 'msfadmin', :ptype => 'ssh_pubkey')
        expect(cred.ptype_human).to eq('SSH public key')
      end
    end

    context '#ssh_key_id' do
      it 'should return nil if not an ssh_key' do
        cred = FactoryBot.build(:mdm_cred, :user => 'msfadmin', :pass => 'msfadmin', :ptype => 'password_rw')
        expect(cred.ssh_key_id).to eq(nil)
      end

      it 'should return nil if proof does not contain the key id' do
        cred = FactoryBot.build(:mdm_cred, :user => 'msfadmin', :pass => '/path/to/keyfile', :ptype => 'ssh_key', :proof => "no key here")
        expect(cred.ssh_key_id).to eq(nil)
      end

      it 'should return the key id for an ssh_key' do
        cred = FactoryBot.build(:mdm_cred, :user => 'msfadmin', :pass => '/path/to/keyfile', :ptype => 'ssh_key', :proof => "KEY=57:c3:11:5d:77:c5:63:90:33:2d:c5:c4:99:78:62:7a")
        expect(cred.ssh_key_id).to eq('57:c3:11:5d:77:c5:63:90:33:2d:c5:c4:99:78:62:7a')
      end

    end

    context '#ssh_key_matches?' do
      it 'should return true if the ssh_keys match' do
        other_ssh_key = FactoryBot.create(
            :mdm_cred,
            pass: '/path/to/keyfile',
            proof: 'KEY=57:c3:11:5d:77:c5:63:90:33:2d:c5:c4:99:78:62:7a',
            ptype: 'ssh_key',
            service: other_service,
            user: 'msfadmin'
        )

        expect(other_ssh_key.ssh_key_matches?(ssh_key)).to eq(true)
      end

      it 'should return false if passed something other than a cred' do
        expect(ssh_key.ssh_key_matches?(service)).to eq(false)
      end

      it 'should return false if the ptypes do not match' do
        different_ptype = FactoryBot.create(
            :mdm_cred,
            pass: '/path/to/keyfile',
            proof: 'KEY=57:c3:11:5d:77:c5:63:90:33:2d:c5:c4:99:78:62:7a',
            ptype: 'ssh_pubkey',
            service: other_service,
            user: 'msfadmin'
        )

        expect(different_ptype.ssh_key_matches?(ssh_key)).to eq(false)
      end

      it 'should return false if the key ids do not match' do
        different_proof = FactoryBot.create(
            :mdm_cred,
            pass: '/path/to/keyfile',
            proof: 'KEY=66:d4:22:6e:88:d6:74:A1:44:3e:d6:d5:AA:89:73:8b',
            ptype: 'ssh_pubkey',
            service: other_service,
            user: 'msfadmin'
        )

        expect(different_proof.ssh_key_matches?(ssh_key)).to eq(false)
      end

      it 'should behave the same for public keys as private keys' do
        pubkey2 = FactoryBot.create(:mdm_cred, :service => service, :user => 'msfadmin', :pass => '/path/to/keyfile', :ptype => 'ssh_pubkey', :proof => "KEY=57:c3:11:5d:77:c5:63:90:33:2d:c5:c4:99:78:62:7a")
        pubkey3 = FactoryBot.create(:mdm_cred, :service => service, :user => 'msfadmin', :pass => '/path/to/keyfile', :ptype => 'ssh_pubkey', :proof => "KEY=66:d4:22:6e:88:d6:74:A1:44:3e:d6:d5:AA:89:73:8b")
        expect(pubkey2.ssh_key_matches?(ssh_pubkey)).to eq(true)
        expect(pubkey2.ssh_key_matches?(pubkey3)).to eq(false)
      end

      it 'should always return false for non ssh key creds' do
        cred2 = FactoryBot.create(:mdm_cred, :service => other_service, :ptype => 'password', :user => 'msfadmin', :pass => 'msfadmin' )
        cred3 = FactoryBot.create(:mdm_cred, :service => other_service, :ptype => 'password', :user => 'msfadmin', :pass => 'msfadmin' )
        expect(cred2.ssh_key_matches?(cred3)).to eq(false)
      end
    end

    context '#ssh_keys' do
      #
      # lets
      #

      let(:other_ssh_key) {
        FactoryBot.create(
            :mdm_cred,
            pass: '/path/to/keyfile',
            proof: 'KEY=57:c3:11:5d:77:c5:63:90:33:2d:c5:c4:99:78:62:7a',
            ptype: 'ssh_key',
            service: other_service,
            user: 'msfadmin'
        )
      }

      #
      # Callbacks
      #

      before(:example) do
        ssh_key
        ssh_pubkey
      end

      it 'should return all ssh private keys with a matching id' do
        expect(other_ssh_key.ssh_keys).to include(ssh_key)
      end

      it 'should return all ssh public keys with a matching id' do
        expect(other_ssh_key.ssh_keys).to include(ssh_pubkey)
      end
    end

    context '#ssh_private_keys' do
      #
      # lets
      #

      let(:other_ssh_key) {
        FactoryBot.create(
            :mdm_cred,
            pass: '/path/to/keyfile',
            proof: 'KEY=57:c3:11:5d:77:c5:63:90:33:2d:c5:c4:99:78:62:7a',
            ptype: 'ssh_key',
            service: other_service,
            user: 'msfadmin',
        )
      }

      #
      # Callbacks
      #

      before(:example) do
        ssh_key
        ssh_pubkey
      end

      it 'should return ssh private keys with matching ids' do
        expect(other_ssh_key.ssh_private_keys).to include(ssh_key)
      end

      it 'should not return ssh public keys with matching ids' do
        expect(other_ssh_key.ssh_private_keys).not_to include(ssh_pubkey)
      end
    end

    context '#ssh_public_keys' do
      #
      # lets
      #

      let(:other_ssh_key) {
        FactoryBot.create(
            :mdm_cred,
            pass: '/path/to/keyfile',
            proof: 'KEY=57:c3:11:5d:77:c5:63:90:33:2d:c5:c4:99:78:62:7a',
            ptype: 'ssh_key',
            service: other_service,
            user: 'msfadmin'
        )
      }

      #
      # Callbacks
      #

      before(:example) do
        ssh_key
        ssh_pubkey
      end

      it 'should not return ssh private keys with matching ids' do
        expect(other_ssh_key.ssh_public_keys).not_to include(ssh_key)
      end

      it 'should return ssh public keys with matching ids' do
        expect(other_ssh_key.ssh_public_keys).to include(ssh_pubkey)
      end
    end
  end

  context 'factory' do
    it 'should be valid' do
      cred = FactoryBot.build(:mdm_cred)
      expect(cred).to be_valid
    end
  end

end
