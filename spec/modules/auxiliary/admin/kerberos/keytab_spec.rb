require 'rspec'

RSpec.describe 'kerberos keytab' do
  include_context 'Msf::UIDriver'
  include_context 'Msf::DBManager'
  include_context 'Msf::Simple::Framework#modules loading'

  let(:subject) do
    load_and_create_module(
      module_type: 'auxiliary',
      reference_name: 'admin/kerberos/keytab'
    )
  end

=begin
  Generated with heimdal ktutil; which has two additional bytes at the end for a 32-bit kvno and flags which are
  not present in the mit format

  rm -f heimdal.keytab
  ktutil --keytab=./heimdal.keytab --verbose add --password=password --principal=Administrator@DOMAIN.LOCAL --enctype=aes256-cts-hmac-sha1-96 --kvno=1
  ktutil --keytab=./heimdal.keytab --verbose add --password=password --principal=Administrator@DOMAIN.LOCAL --enctype=aes128-cts-hmac-sha1-96 --kvno=1
  ktutil --keytab=./heimdal.keytab --verbose add --password=password --principal=Administrator@DOMAIN.LOCAL --enctype=arcfour-hmac-md5 --kvno=1
  ktutil --keytab=./heimdal.keytab --verbose list

  ruby -r 'active_support/core_ext/array' -e 'puts File.binread("./heimdal.keytab").bytes.map { |x| "\\x#{x.to_s(16).rjust(2, "0")}" }.in_groups_of(16).map { |row| "\"#{row.join("")}\"" }.join(" \\ \n")'
=end
  let(:valid_keytab) do
    "\x05\x02\x00\x00\x00\x54\x00\x01\x00\x0c\x44\x4f\x4d\x41\x49\x4e" \
    "\x2e\x4c\x4f\x43\x41\x4c\x00\x0d\x41\x64\x6d\x69\x6e\x69\x73\x74" \
    "\x72\x61\x74\x6f\x72\x00\x00\x00\x01\x63\x38\x7e\x21\x01\x00\x12" \
    "\x00\x20\xc4\xa3\xf3\x1d\x64\xaf\xa6\x48\xa6\xd0\x8d\x07\x76\x56" \
    "\x3e\x12\x38\xb9\x76\xd0\xb9\x0f\x79\xea\x07\x21\x94\x36\x82\x94" \
    "\xe9\x29\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x44\x00\x01" \
    "\x00\x0c\x44\x4f\x4d\x41\x49\x4e\x2e\x4c\x4f\x43\x41\x4c\x00\x0d" \
    "\x41\x64\x6d\x69\x6e\x69\x73\x74\x72\x61\x74\x6f\x72\x00\x00\x00" \
    "\x01\x63\x38\x7e\x21\x01\x00\x11\x00\x10\xba\xba\x43\xa8\xb9\x7b" \
    "\xac\xa1\x53\xbd\x54\xb2\xf0\x77\x4a\xd7\x00\x00\x00\x01\x00\x00" \
    "\x00\x00\x00\x00\x00\x44\x00\x01\x00\x0c\x44\x4f\x4d\x41\x49\x4e" \
    "\x2e\x4c\x4f\x43\x41\x4c\x00\x0d\x41\x64\x6d\x69\x6e\x69\x73\x74" \
    "\x72\x61\x74\x6f\x72\x00\x00\x00\x01\x63\x38\x7e\x21\x01\x00\x17" \
    "\x00\x10\x88\x46\xf7\xea\xee\x8f\xb1\x17\xad\x06\xbd\xd8\x30\xb7" \
    "\x58\x6c\x00\x00\x00\x01\x00\x00\x00\x00"
  end
  let(:keytab_file) { Tempfile.new('keytab') }

  before(:each) do
    Timecop.freeze(Time.parse('Jul 15, 2022 12:33:40.000000000 GMT'))
    subject.datastore['VERBOSE'] = false
    allow(driver).to receive(:input).and_return(driver_input)
    allow(driver).to receive(:output).and_return(driver_output)
    subject.init_ui(driver_input, driver_output)
  end

  after(:each) do
    Timecop.return
  end

  describe '#add_keytab_entry' do
    context 'when the keytab file does not exist' do
      before(:each) do
        File.delete(keytab_file.path)
        subject.datastore['KEYTAB_FILE'] = keytab_file.path
      end

      context 'when supplying a key with aes126 encryption type' do
        it 'creates a new keytab' do
          subject.datastore['PRINCIPAL'] = 'Administrator'
          subject.datastore['REALM'] = 'DOMAIN.LOCAL'
          subject.datastore['KVNO'] = 1
          subject.datastore['ENCTYPE'] = 'AES256'
          subject.datastore['KEY'] = 'c4a3f31d64afa648a6d08d0776563e1238b976d0b90f79ea072194368294e929'
          subject.add_keytab_entry

          subject.list_keytab_entries
          expect(@combined_output.join("\n")).to match_table <<~TABLE
          keytab saved to #{keytab_file.path}
          Keytab entries
          ==============

           kvno  type         principal                   hash                                                              date
           ----  ----         ---------                   ----                                                              ----
           1     18 (AES256)  Administrator@DOMAIN.LOCAL  c4a3f31d64afa648a6d08d0776563e1238b976d0b90f79ea072194368294e929  #{Time.parse('1970-01-01 00:00:00 +0000').to_time}
          TABLE
        end
      end

      context 'when supplying a password with the ALL encryption type specified' do
        it 'creates a new keytab' do
          subject.datastore['PRINCIPAL'] = 'Administrator'
          subject.datastore['REALM'] = 'DOMAIN.LOCAL'
          subject.datastore['KVNO'] = 1
          subject.datastore['ENCTYPE'] = 'ALL'
          subject.datastore['PASSWORD'] = 'password'
          subject.add_keytab_entry

          subject.list_keytab_entries
          expect(@combined_output.join("\n")).to match_table <<~TABLE
          keytab saved to #{keytab_file.path}
          Keytab entries
          ==============

           kvno  type                principal                   hash                                                              date
           ----  ----                ---------                   ----                                                              ----
           1     3  (DES_CBC_MD5)    Administrator@DOMAIN.LOCAL  89d3b923d6a7195e                                                  #{Time.parse('1970-01-01 00:00:00 +0000').to_time}
           1     16 (DES3_CBC_SHA1)  Administrator@DOMAIN.LOCAL  341994e0ba5b1a20d640911cda23c137b637d51a6416d6cb                  #{Time.parse('1970-01-01 00:00:00 +0000').to_time}
           1     23 (RC4_HMAC)       Administrator@DOMAIN.LOCAL  8846f7eaee8fb117ad06bdd830b7586c                                  #{Time.parse('1970-01-01 00:00:00 +0000').to_time}
           1     17 (AES128)         Administrator@DOMAIN.LOCAL  baba43a8b97baca153bd54b2f0774ad7                                  #{Time.parse('1970-01-01 00:00:00 +0000').to_time}
           1     18 (AES256)         Administrator@DOMAIN.LOCAL  c4a3f31d64afa648a6d08d0776563e1238b976d0b90f79ea072194368294e929  #{Time.parse('1970-01-01 00:00:00 +0000').to_time}

          TABLE
        end
      end

      context 'when supplying a password with aes256 encryption type' do
        it 'creates a new keytab' do
          subject.datastore['PRINCIPAL'] = 'Administrator'
          subject.datastore['REALM'] = 'DOMAIN.LOCAL'
          subject.datastore['KVNO'] = 1
          subject.datastore['ENCTYPE'] = 'AES256'
          subject.datastore['PASSWORD'] = 'password'
          subject.add_keytab_entry

          subject.list_keytab_entries
          expect(@combined_output.join("\n")).to match_table <<~TABLE
          keytab saved to #{keytab_file.path}
          Keytab entries
          ==============

           kvno  type         principal                   hash                                                              date
           ----  ----         ---------                   ----                                                              ----
           1     18 (AES256)  Administrator@DOMAIN.LOCAL  c4a3f31d64afa648a6d08d0776563e1238b976d0b90f79ea072194368294e929  #{Time.parse('1970-01-01 00:00:00 +0000').to_time}
          TABLE
        end
      end
    end

    context 'when the keytab file exists' do
      before(:each) do
        File.binwrite(keytab_file.path, valid_keytab)
        subject.datastore['KEYTAB_FILE'] = keytab_file.path
      end

      context 'when supplying a password with aes256 encryption type' do
        it 'updates the existing keytab' do
          subject.datastore['PRINCIPAL'] = 'Administrator'
          subject.datastore['REALM'] = 'DOMAIN.LOCAL'
          subject.datastore['KVNO'] = 1
          subject.datastore['ENCTYPE'] = 'AES256'
          subject.datastore['PASSWORD'] = 'password'
          subject.add_keytab_entry

          subject.list_keytab_entries
          expect(@combined_output.join("\n")).to match_table <<~TABLE
            keytab saved to #{keytab_file.path}
            Keytab entries
            ==============

             kvno  type           principal                   hash                                                              date
             ----  ----           ---------                   ----                                                              ----
             1     18 (AES256)    Administrator@DOMAIN.LOCAL  c4a3f31d64afa648a6d08d0776563e1238b976d0b90f79ea072194368294e929  #{Time.parse('2022-10-01 17:51:29 +0000').to_time}
             1     17 (AES128)    Administrator@DOMAIN.LOCAL  baba43a8b97baca153bd54b2f0774ad7                                  #{Time.parse('2022-10-01 17:51:29 +0000').to_time}
             1     23 (RC4_HMAC)  Administrator@DOMAIN.LOCAL  8846f7eaee8fb117ad06bdd830b7586c                                  #{Time.parse('2022-10-01 17:51:29 +0000').to_time}
             1     18 (AES256)    Administrator@DOMAIN.LOCAL  c4a3f31d64afa648a6d08d0776563e1238b976d0b90f79ea072194368294e929  #{Time.parse('1970-01-01 00:00:00 +0000').to_time}
          TABLE
        end
      end
    end
  end

  describe '#list_keytab_entries' do
    context 'when the keytab file does not exist' do
      it 'raises a config error' do
        expect { subject.list_keytab_entries }.to raise_error Msf::Auxiliary::Failed, /Invalid key tab file/
      end
    end

    context 'when the keytab file exists' do
      before(:each) do
        File.binwrite(keytab_file.path, valid_keytab)
        subject.datastore['KEYTAB_FILE'] = keytab_file.path
      end

      it 'lists the available keytab entries' do
        subject.list_keytab_entries
        expect(@combined_output.join("\n")).to match_table <<~TABLE
          Keytab entries
          ==============

           kvno  type           principal                   hash                                                              date
           ----  ----           ---------                   ----                                                              ----
           1     18 (AES256)    Administrator@DOMAIN.LOCAL  c4a3f31d64afa648a6d08d0776563e1238b976d0b90f79ea072194368294e929  #{Time.parse('2022-10-01 17:51:29 +0000').to_time}
           1     17 (AES128)    Administrator@DOMAIN.LOCAL  baba43a8b97baca153bd54b2f0774ad7                                  #{Time.parse('2022-10-01 17:51:29 +0000').to_time}
           1     23 (RC4_HMAC)  Administrator@DOMAIN.LOCAL  8846f7eaee8fb117ad06bdd830b7586c                                  #{Time.parse('2022-10-01 17:51:29 +0000').to_time}

        TABLE
      end
    end
  end

  describe '#export_keytab_entries' do
    context 'when the keytab file does not exist' do
      before(:each) do
        File.delete(keytab_file.path)
        subject.datastore['KEYTAB_FILE'] = keytab_file.path
        framework.db.delete_credentials(ids: (framework.db.creds || []).map(&:id))
      end

      after(:each) do
        framework.db.delete_credentials(ids: (framework.db.creds || []).map(&:id))
      end

      context 'when there is no database active' do
        before(:each) do
          allow(subject.framework.db).to receive(:active).and_return(false)
        end

        it 'notifies the user that there is no database active' do
          subject.export_keytab_entries

          expect(@combined_output.join("\n")).to match_table <<~TABLE
            export not available, because the database is not active.
          TABLE
        end
      end

      context 'when there are no kerberos or ntlm creds present in the database' do
        it 'notifies the user that there are no entries to export' do
          subject.export_keytab_entries

          expect(@combined_output.join("\n")).to match_table <<~TABLE
            No entries to export
            keytab saved to #{keytab_file.path} 

          TABLE
        end
      end

      context 'when there are kerberos and ntlm creds present in the database' do
        def report_creds(
          user, hash, type: :ntlm_hash, jtr_format: '', realm_key: nil, realm_value: nil,
          rhost: '192.0.2.2', rport: '445', myworkspace_id: nil, module_fullname: nil
        )
          service_data = {
            address: rhost,
            port: rport,
            service_name: 'smb',
            protocol: 'tcp',
            workspace_id: myworkspace_id
          }
          credential_data = {
            module_fullname: module_fullname,
            origin_type: :service,
            private_data: hash,
            private_type: type,
            jtr_format: jtr_format,
            username: user
          }.merge(service_data)
          credential_data[:realm_key] = realm_key if realm_key
          credential_data[:realm_value] = realm_value if realm_value

          cl = framework.db.create_credential_and_login(credential_data)
          cl.respond_to?(:core_id) ? cl.core_id : nil
        end

        before(:each) do
          report_creds(
            'user_without_realm', 'aad3b435b51404eeaad3b435b51404ee:e02bc503339d51f71d913c245d35b50b',
            type: :ntlm_hash, module_fullname: subject.fullname, myworkspace_id: framework.db.default_workspace.id
          )
          report_creds(
            'user_with_realm', 'aad3b435b51404eeaad3b435b51404ee:32ede47af254546a82b1743953cc4950',
            type: :ntlm_hash, module_fullname: subject.fullname, myworkspace_id: framework.db.default_workspace.id,
            realm_key: Metasploit::Model::Realm::Key::ACTIVE_DIRECTORY_DOMAIN, realm_value: 'example.local'
          )
          krb_key = {
            enctype: Rex::Proto::Kerberos::Crypto::Encryption::AES256,
            salt: "DEMO.LOCALuser_with_krbkey".b,
            key: 'c4a3f31d64afa648a6d08d0776563e1238b976d0b90f79ea072194368294e929'
          }
          report_creds(
            'user_with_krbkey', Metasploit::Credential::KrbEncKey.build_data(**krb_key),
            type: :krb_enc_key, module_fullname: subject.fullname, myworkspace_id: framework.db.default_workspace.id,
            realm_key: Metasploit::Model::Realm::Key::ACTIVE_DIRECTORY_DOMAIN, realm_value: 'demo.local'
          )
        end

        it 'exports the creds' do
          subject.export_keytab_entries
          subject.list_keytab_entries

          expect(@combined_output.join("\n")).to match_table <<~TABLE
            keytab saved to #{keytab_file.path}
            Keytab entries
            ==============
            
             kvno  type           principal                      hash                                                                                                                              date
             ----  ----           ---------                      ----                                                                                                                              ----
             1     23 (RC4_HMAC)  user_without_realm@            e02bc503339d51f71d913c245d35b50b                                                                                                  #{Time.parse('1970-01-01 01:00:00 +0100').to_time}
             1     23 (RC4_HMAC)  user_with_realm@example.local  32ede47af254546a82b1743953cc4950                                                                                                  #{Time.parse('1970-01-01 01:00:00 +0100').to_time}
             1     18 (AES256)    user_with_krbkey@demo.local    63346133663331643634616661363438613664303864303737363536336531323338623937366430623930663739656130373231393433363832393465393239  #{Time.parse('1970-01-01 01:00:00 +0100').to_time}

          TABLE
        end
      end
    end
  end
end
