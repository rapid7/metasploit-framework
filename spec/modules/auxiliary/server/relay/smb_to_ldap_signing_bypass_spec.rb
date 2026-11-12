require 'spec_helper'
require 'msf/core/exploit/remote/relay/target_list'

RSpec.describe 'auxiliary/server/relay/smb_to_ldap_signing_bypass' do
  include_context 'Msf::Simple::Framework#modules loading'

  subject(:mod) do
    load_and_create_module(
      module_type: 'auxiliary',
      reference_name: 'server/relay/smb_to_ldap_signing_bypass'
    )
  end

  let(:target_dn) { 'CN=RESOURCE,CN=Computers,DC=example,DC=test' }
  let(:delegate_sid) { 'S-1-5-21-111-222-333-1100' }
  let(:existing_sid) { 'S-1-5-21-111-222-333-1200' }
  let(:rbcd_attribute) { 'msDS-AllowedToActOnBehalfOfOtherIdentity' }
  let(:ldap) { instance_double(Rex::Proto::LDAP::Client) }
  let(:relay_target) do
    Msf::Exploit::Remote::Relay::Target.new(ip: '192.0.2.10', port: 389, protocol: :ldap)
  end
  let(:entry) { Net::LDAP::Entry.new(target_dn) }
  let(:current_value) do
    mod.adds_build_rbcd_security_descriptor(Rex::Proto::MsDtyp::MsDtypSid.new(existing_sid)).to_binary_s
  end
  let(:operation) { mod.send(:prepare_relay_operation, ldap, nil, relay_target) }

  before do
    mod.datastore['RHOSTS'] = '192.0.2.10'
    mod.datastore['TARGET_ACCOUNT'] = target_dn
    mod.datastore['DELEGATE_FROM'] = delegate_sid
  end

  describe '#validate' do
    it 'accepts anonymous bootstrap with the default preservation behavior' do
      expect { mod.validate }.not_to raise_error
    end

    context 'when using shadow credentials' do
      before do
        mod.datastore['ACTION'] = 'SHADOW_CREDENTIALS'
        mod.datastore['DELEGATE_FROM'] = nil
      end

      it 'accepts anonymous bootstrap with a full target DN and no delegate SID' do
        expect { mod.validate }.not_to raise_error
      end

      it 'rejects an account name before starting an anonymous relay' do
        mod.datastore['TARGET_ACCOUNT'] = 'Administrator'

        expect { mod.validate }.to raise_error(Msf::OptionValidateError) { |error|
          expect(error.reasons['TARGET_ACCOUNT']).to include(/full target DN/)
        }
      end

      it 'rejects a SID because the target identifier must be a DN' do
        mod.datastore['TARGET_ACCOUNT'] = delegate_sid

        expect { mod.validate }.to raise_error(Msf::OptionValidateError, /TARGET_ACCOUNT/)
      end

      it 'continues to accept account names with credentialed bootstrap' do
        mod.datastore['BOOTSTRAP_AUTH'] = 'NTLM'
        mod.datastore['LDAPDomain'] = 'example.test'
        mod.datastore['LDAPUsername'] = 'directory-reader'
        mod.datastore['LDAPPassword'] = 'test-password'
        mod.datastore['TARGET_ACCOUNT'] = 'Administrator'

        expect { mod.validate }.not_to raise_error
      end
    end

    context 'when overwrite is enabled' do
      before do
        mod.datastore['RBCDOverwrite'] = true
      end

      it 'accepts a target DN and direct delegate SID without credentials' do
        expect { mod.validate }.not_to raise_error
      end

      it 'rejects a target name that would require a directory lookup' do
        mod.datastore['TARGET_ACCOUNT'] = 'RESOURCE$'

        expect { mod.validate }.to raise_error(Msf::OptionValidateError, /TARGET_ACCOUNT/)
      end

      it 'rejects a delegate name that would require a directory lookup' do
        mod.datastore['DELEGATE_FROM'] = 'CONTROLLED$'

        expect { mod.validate }.to raise_error(Msf::OptionValidateError, /DELEGATE_FROM/)
      end

      it 'rejects a malformed delegate SID' do
        mod.datastore['DELEGATE_FROM'] = 'S-invalid'

        expect { mod.validate }.to raise_error(Msf::OptionValidateError, /DELEGATE_FROM/)
      end
    end
  end

  describe '#prepare_relay_operation' do
    context 'when using anonymous shadow credentials' do
      before do
        mod.datastore['ACTION'] = 'SHADOW_CREDENTIALS'
        mod.datastore['TARGET_ACCOUNT'] = 'CN=LabUser,CN=Users,DC=example,DC=test'
        mod.datastore['DELEGATE_FROM'] = nil
        allow(mod).to receive(:store_loot).and_return('/tmp/shadow.pfx', '/tmp/shadow_recovery.txt')
      end

      it 'prepares an attribute add for the exact target DN without any directory searches' do
        expect(ldap).not_to receive(:search)

        expect(operation).to have_attributes(
          dn: mod.datastore['TARGET_ACCOUNT'],
          attribute: 'msDS-KeyCredentialLink',
          type: :add
        )
      end

      it 'retains the exact added value for removal without replacing existing credentials' do
        prepared = operation

        expect(prepared.recovery[:value]).to eq(prepared.attribute_values.first)
      end
    end

    context 'when overwrite is disabled' do
      before do
        allow(ldap).to receive(:search).and_return([entry])
        allow(ldap).to receive(:get_operation_result).and_return(OpenStruct.new(code: Net::LDAP::ResultCodeSuccess))
        allow(mod).to receive(:store_rbcd_backup).and_return('/tmp/original_rbcd.bin')
      end

      context 'when an existing descriptor is readable' do
        before do
          entry[rbcd_attribute] = [current_value]
        end

        it 'preserves existing entries when preparing the replacement' do
          descriptor = Rex::Proto::MsDtyp::MsDtypSecurityDescriptor.read(operation.attribute_values.first)

          expect(descriptor.dacl.aces.map { |ace| ace.body.sid.to_s }).to eq([existing_sid, delegate_sid])
        end

        it 'stores the exact original descriptor for recovery' do
          expect(mod).to receive(:store_rbcd_backup).with(relay_target, target_dn, current_value)

          operation
        end

        it 'uses a replacement to merge the new ACE with existing entries' do
          expect(operation.type).to eq(:replace)
        end

        it 'stops if the existing descriptor cannot be backed up' do
          allow(mod).to receive(:store_rbcd_backup).and_return(nil)

          expect { operation }.to raise_error(
            Msf::Exploit::Remote::Relay::NTLM::Target::LDAP::ReauthenticationClient::PreparationError,
            /recovery information could not be persisted/
          )
        end
      end

      it 'uses an attribute add when the descriptor is absent or hidden, preserving unknown existing data' do
        expect(operation.type).to eq(:add)
      end

      it 'does not treat anonymous bootstrap as permission to skip a failed read' do
        allow(ldap).to receive(:search).and_return([])

        expect { operation }.to raise_error(
          Msf::Exploit::Remote::Relay::NTLM::Target::LDAP::ReauthenticationClient::LookupError,
          /was not readable/
        )
      end

      it 'explains that a missing name may be invisible to the bootstrap identity' do
        mod.datastore['TARGET_ACCOUNT'] = 'Administrator'
        mod.datastore['BASE_DN'] = 'DC=example,DC=test'
        allow(ldap).to receive(:search).and_return([])

        expect { operation }.to raise_error(
          Msf::Exploit::Remote::Relay::NTLM::Target::LDAP::ReauthenticationClient::LookupError,
          /not found or is not visible to the ANONYMOUS bootstrap identity/
        )
      end
    end

    context 'when overwrite is enabled' do
      before do
        mod.datastore['RBCDOverwrite'] = true
      end

      it 'prepares the replacement without target, delegate, or descriptor searches' do
        expect(ldap).not_to receive(:search)

        expect(operation.type).to eq(:replace)
      end

      it 'builds a descriptor containing only the requested delegate' do
        descriptor = Rex::Proto::MsDtyp::MsDtypSecurityDescriptor.read(operation.attribute_values.first)

        expect(descriptor.dacl.aces.map { |ace| ace.body.sid.to_s }).to eq([delegate_sid])
      end

      it 'records the original state as unknown instead of claiming the attribute was absent' do
        expect(operation.recovery).to include(original_present: nil, overwrite: true, backup_path: nil)
      end

      it 'does not claim to have backed up an unread descriptor' do
        expect(mod).not_to receive(:store_rbcd_backup)

        operation
      end
    end
  end

  describe '#relay_targets' do
    it 'prepares anonymous overwrite with the running job options instead of a previous module configuration' do
      mod.datastore['TARGET_ACCOUNT'] = 'Administrator'
      old_job = mod.replicant
      mod.datastore['TARGET_ACCOUNT'] = target_dn
      mod.datastore['RBCDOverwrite'] = true
      new_job = mod.replicant
      target = new_job.relay_targets.next(nil)

      expect(ldap).not_to receive(:search)
      prepared = target.protocol_options[:operation_preparer].call(ldap, nil, target)

      expect(prepared.dn).to eq(target_dn)
      expect(prepared.type).to eq(:replace)
      expect(old_job.datastore['TARGET_ACCOUNT']).to eq('Administrator')
    end
  end

  describe '#run' do
    it 'warns about loss of delegation entries before starting the listener when overwrite is enabled' do
      mod.datastore['RBCDOverwrite'] = true
      allow(mod).to receive(:service).and_return(nil)

      expect(mod).to receive(:print_warning).with(/Existing delegation entries may be lost and cannot be restored/).ordered
      expect(mod).to receive(:start_service).ordered

      mod.run
    end
  end

  describe '#report_relay_outcome' do
    it 'does not claim that removing the added ACE restores overwritten entries' do
      mod.datastore['RBCDOverwrite'] = true
      outcome = Msf::Exploit::Remote::Relay::NTLM::Target::LDAP::ReauthenticationClient::Outcome.new(
        authentication: :success,
        modification: :unconfirmed,
        reason: 'Connection closed before the modification result was received'
      )
      connection = instance_double(
        Msf::Exploit::Remote::Relay::NTLM::Target::LDAP::ReauthenticationClient,
        outcome: outcome,
        operation: operation
      )

      expect(mod).to receive(:print_warning).with(/Modification is unconfirmed/)
      expect(mod).to receive(:print_warning).with(/Removing the added ACE cannot restore overwritten entries/)

      mod.send(:report_relay_outcome, connection, 'EXAMPLE\\labadmin')
    end
  end
end
