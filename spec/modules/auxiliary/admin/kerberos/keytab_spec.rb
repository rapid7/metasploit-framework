require 'rspec'

RSpec.describe 'kerberos keytab' do
  include_context 'Msf::UIDriver'
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
    subject.datastore['VERBOSE'] = false
    allow(driver).to receive(:input).and_return(driver_input)
    allow(driver).to receive(:output).and_return(driver_output)
    subject.init_ui(driver_input, driver_output)
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
          expect(@output.join("\n")).to match_table <<~TABLE
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
          expect(@output.join("\n")).to match_table <<~TABLE
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
          expect(@output.join("\n")).to match_table <<~TABLE
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
          expect(@output.join("\n")).to match_table <<~TABLE
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
        expect(@output.join("\n")).to match_table <<~TABLE
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
end
