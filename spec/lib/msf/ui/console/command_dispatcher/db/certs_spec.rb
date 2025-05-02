RSpec.describe Msf::Ui::Console::CommandDispatcher::Db::Certs do

  if ENV['REMOTE_DB']
    before {skip('Not supported for remote DB')}
  end

  include_context 'Msf::DBManager'
  include_context 'Msf::UIDriver'

  # Replace table entry ids with `[id]` for matching simplicity
  # Also corrects spacing between columns to remove variation from different length ids
  def table_without_ids(table)
    output = table.dup
    output.gsub!(/^--\s+--------/, '--    --------')
    output.gsub!(/^id\s+username/, 'id    username')
    output.gsub!(/^\d+\s+/, '[id]  ')
  end

  subject do
    described_class = self.described_class
    instance = Class.new do
      include Msf::Ui::Console::CommandDispatcher
      include Msf::Ui::Console::CommandDispatcher::Common
      include Msf::Ui::Console::CommandDispatcher::Db::Common
      include described_class
    end.new(driver)
    instance
  end

  describe '#cmd_certs' do
    context 'when the -h option is provided' do
      it 'should show a help message' do
        subject.cmd_certs('-h')
        expect(@output.join("\n")).to match_table <<~TABLE
          List Pkcs12 certificate bundles in the database
          Usage: certs [options] [username[@domain_upn_format]]

          OPTIONS:

              -a, --activate    Activates *all* matching pkcs12 entries
              -A, --deactivate  Deactivates *all* matching pkcs12 entries
              -d, --delete      Delete *all* matching pkcs12 entries
              -e, --export      The file path where to export the matching pkcs12 entry
              -h, --help        Help banner
              -i, --index       Pkcs12 entry ID(s) to search for, e.g. `-i 1` or `-i 1,2,3` or `-i 1 -i 2 -i 3`
              -v, --verbose     Verbose output
        TABLE
      end
    end

    context 'when there are no Pkcs12 certs' do
      context 'when no options are provided' do
        it 'should show no Pkcs12' do
          subject.cmd_certs
          expect(@output.join("\n")).to match_table <<~TABLE
            Pkcs12
            ======
            No Pkcs12
          TABLE
        end
      end

      context 'when the -v option is provided' do
        it 'should show no Pkcs12' do
          subject.cmd_certs('-v')
          expect(@output.join("\n")).to match_table <<~TABLE
            Pkcs12
            ======
            No Pkcs12
          TABLE
        end
      end

      context 'when the -i option is provided' do
        it 'should show no Pkcs12 and missing id warning' do
          subject.cmd_certs('-i', '0') # Can't have an id of 0
          expect(@combined_output.join("\n")).to match_table <<~TABLE
            Not all records with the ids: ["0"] could be found.
            Please ensure all ids specified are available.
            Pkcs12
            ======
            No Pkcs12
          TABLE
        end
      end
    end

    context 'when there are Pkcs12 certs' do
      let(:username1) { 'n00tmeg' }
      let(:realm1) { 'test_realm1' }
      let(:username2) { 'msfuser' }
      let(:realm2) { 'test_realm2' }
      let(:username3) { 'msftest' }
      let(:realm3) { 'test_realm3' }
      let(:origin) do
        FactoryBot.create(
          :metasploit_credential_origin_service,
          service: FactoryBot.create(
            :mdm_service,
            host: FactoryBot.create(:mdm_host, workspace: framework.db.default_workspace)
          )
        )
      end
      let!(:creds) do
        [
            FactoryBot.create(
            :metasploit_credential_core,
            public: FactoryBot.create(:metasploit_credential_username, username: username1),
            realm: FactoryBot.create(:metasploit_credential_realm, value: realm1),
            private: FactoryBot.create(:metasploit_credential_pkcs12),
            origin: origin
          ),
            FactoryBot.create(
            :metasploit_credential_core,
            public: FactoryBot.create(:metasploit_credential_username, username: username2),
            realm: FactoryBot.create(:metasploit_credential_realm, value: realm2),
            private: FactoryBot.create(:metasploit_credential_pkcs12),
            origin: origin
          )
        ]
      end

      context 'when no options are provided' do
        it 'should show Pkcs12 certs' do
          subject.cmd_certs
          expect(table_without_ids(@output.join("\n"))).to match_table <<~TABLE
            Pkcs12
            ======
            id    username  realm        subject                       issuer                        ADCS CA  ADCS Template  status
            --    --------  -----        -------                       ------                        -------  -------------  ------
            [id]  n00tmeg   test_realm1  /C=BE/O=Test/OU=Test/CN=Test  /C=BE/O=Test/OU=Test/CN=Test                          active
            [id]  msfuser   test_realm2  /C=BE/O=Test/OU=Test/CN=Test  /C=BE/O=Test/OU=Test/CN=Test                          active
          TABLE
        end
      end

      context 'when a username is specified' do
        it 'should show the matching username' do
          subject.cmd_certs('n00tmeg')
          expect(table_without_ids(@output.join("\n"))).to match_table <<~TABLE
            Pkcs12
            ======
            id    username  realm        subject                       issuer                        ADCS CA  ADCS Template  status
            --    --------  -----        -------                       ------                        -------  -------------  ------
            [id]  n00tmeg   test_realm1  /C=BE/O=Test/OU=Test/CN=Test  /C=BE/O=Test/OU=Test/CN=Test                          active
          TABLE
        end
      end

      context 'with the -i option twice and two different IDs' do
        it 'should show both matching Pkcs12' do
          subject.cmd_certs('-i', "#{creds[0].id}", '-i', "#{creds[1].id}")
          expect(table_without_ids(@output.join("\n"))).to match_table <<~TABLE
            Pkcs12
            ======
            id    username  realm        subject                       issuer                        ADCS CA  ADCS Template  status
            --    --------  -----        -------                       ------                        -------  -------------  ------
            [id]  n00tmeg   test_realm1  /C=BE/O=Test/OU=Test/CN=Test  /C=BE/O=Test/OU=Test/CN=Test                          active
            [id]  msfuser   test_realm2  /C=BE/O=Test/OU=Test/CN=Test  /C=BE/O=Test/OU=Test/CN=Test                          active
          TABLE
        end
      end

      context 'when the -i option is provided with 2 valid ids (quoted and space separated)' do
        it 'should show both matching Pkcs12' do
          subject.cmd_certs('-i', "#{creds[0].id} #{creds[1].id}")
          expect(table_without_ids(@output.join("\n"))).to match_table <<~TABLE
            Pkcs12
            ======
            id    username  realm        subject                       issuer                        ADCS CA  ADCS Template  status
            --    --------  -----        -------                       ------                        -------  -------------  ------
            [id]  n00tmeg   test_realm1  /C=BE/O=Test/OU=Test/CN=Test  /C=BE/O=Test/OU=Test/CN=Test                          active
            [id]  msfuser   test_realm2  /C=BE/O=Test/OU=Test/CN=Test  /C=BE/O=Test/OU=Test/CN=Test                          active
          TABLE
        end
      end

      context 'when the -i option is provided with 2 valid ids (quoted and comma + space separated)' do
        it 'should show both matching Pkcs12' do
          subject.cmd_certs('-i', "#{creds[0].id}, #{creds[1].id}")
          expect(table_without_ids(@output.join("\n"))).to match_table <<~TABLE
            Pkcs12
            ======
            id    username  realm        subject                       issuer                        ADCS CA  ADCS Template  status
            --    --------  -----        -------                       ------                        -------  -------------  ------
            [id]  n00tmeg   test_realm1  /C=BE/O=Test/OU=Test/CN=Test  /C=BE/O=Test/OU=Test/CN=Test                          active
            [id]  msfuser   test_realm2  /C=BE/O=Test/OU=Test/CN=Test  /C=BE/O=Test/OU=Test/CN=Test                          active
          TABLE
        end
      end

      context 'when the -i option is provided an invalid ID' do
        it 'should show a warning and an empty list' do
          subject.cmd_certs('-i', "#{creds.last.id + 1}")
          expect(@combined_output.join("\n")).to match_table <<~TABLE
            Not all records with the ids: ["#{creds.last.id + 1}"] could be found.
            Please ensure all ids specified are available.
            Pkcs12
            ======
            No Pkcs12
          TABLE
        end
      end

      context 'when the -v option is provided' do
        let(:pkcs12_1) { OpenSSL::PKCS12.new(Base64.strict_decode64(creds[0].private.data), '') }
        let(:pkcs12_2) { OpenSSL::PKCS12.new(Base64.strict_decode64(creds[1].private.data), '') }

        it 'should show the output given by OpenSSL::Pkcs12 for every Pkcs12' do
          expected_cert1_output = "#{pkcs12_1.certificate.to_s.chomp}\n#{pkcs12_1.certificate.to_text.chomp}"
          expected_cert2_output = "#{pkcs12_2.certificate.to_s.chomp}\n#{pkcs12_2.certificate.to_text.chomp}"

          subject.cmd_certs '-v'
          expect(@output.join("\n")).to match_table <<~TABLE
            Pkcs12
            ======
            Certificate[0]:
            #{expected_cert1_output}
            Certificate[1]:
            #{expected_cert2_output}
          TABLE
        end

        context 'with a username' do
          it 'should show the output given by OpenSSL::Pkcs12 for the matching Pkcs12' do
            expected_cert1_output = "#{pkcs12_1.certificate.to_s.chomp}\n#{pkcs12_1.certificate.to_text.chomp}"

            subject.cmd_certs('-v', 'n00tmeg')
            expect(@output.join("\n")).to match_table <<~TABLE
              Pkcs12
              ======
              Certificate[0]:
              #{expected_cert1_output}
            TABLE
          end
        end

        context 'with the -i option and an ID' do
          it 'should show the output given by OpenSSL::Pkcs12 for the matching Pkcs12' do
            expected_cert2_output = "#{pkcs12_2.certificate.to_s.chomp}\n#{pkcs12_2.certificate.to_text.chomp}"

            subject.cmd_certs('-v', '-i', "#{creds[1].id}")
            expect(@output.join("\n")).to match_table <<~TABLE
              Pkcs12
              ======
              Certificate[0]:
              #{expected_cert2_output}
            TABLE
          end
        end
      end

      context 'when the -d flag is provided' do
        it 'should delete all the Pkcs12 and show the deleted entries' do
          subject.cmd_certs('-d')
          expect(table_without_ids(@output.join("\n"))).to match_table <<~TABLE
            Pkcs12
            ======
            id    username  realm        subject                       issuer                        ADCS CA  ADCS Template  status
            --    --------  -----        -------                       ------                        -------  -------------  ------
            [id]  n00tmeg   test_realm1  /C=BE/O=Test/OU=Test/CN=Test  /C=BE/O=Test/OU=Test/CN=Test                          active
            [id]  msfuser   test_realm2  /C=BE/O=Test/OU=Test/CN=Test  /C=BE/O=Test/OU=Test/CN=Test                          active
            Deleted 2 entries
          TABLE
          expect(Msf::Exploit::Remote::Pkcs12::Storage.new(framework: framework).pkcs12).to be_empty
        end

        context 'with a username' do
          it 'should delete the matching Pkcs12 and show the single entry' do
            subject.cmd_certs('-d', 'n00tmeg')
            expect(table_without_ids(@output.join("\n"))).to match_table <<~TABLE
              Pkcs12
              ======
              id    username  realm        subject                       issuer                        ADCS CA  ADCS Template  status
              --    --------  -----        -------                       ------                        -------  -------------  ------
              [id]  n00tmeg   test_realm1  /C=BE/O=Test/OU=Test/CN=Test  /C=BE/O=Test/OU=Test/CN=Test                          active
              Deleted 1 entry
            TABLE
            expect(Msf::Exploit::Remote::Pkcs12::Storage.new(framework: framework).pkcs12.size).to eq(creds.size - 1)
          end
        end

        context 'with the -i option and an ID' do
          it 'should delete the matching Pkcs12 and show the single entry' do
            subject.cmd_certs('-d', '-i', "#{creds[1].id}")
            expect(table_without_ids(@output.join("\n"))).to match_table <<~TABLE
              Pkcs12
              ======
              id    username  realm        subject                       issuer                        ADCS CA  ADCS Template  status
              --    --------  -----        -------                       ------                        -------  -------------  ------
              [id]  msfuser   test_realm2  /C=BE/O=Test/OU=Test/CN=Test  /C=BE/O=Test/OU=Test/CN=Test                          active
              Deleted 1 entry
            TABLE
            expect(Msf::Exploit::Remote::Pkcs12::Storage.new(framework: framework).pkcs12.size).to eq(creds.size - 1)
          end
        end
      end

      context 'when the -A option is provided' do
        it 'should deactivate all the Pkcs12 and show the deactivated entries' do
          subject.cmd_certs('-A')
          expect(table_without_ids(@output.join("\n"))).to match_table <<~TABLE
            Pkcs12
            ======
            id    username  realm        subject                       issuer                        ADCS CA  ADCS Template  status
            --    --------  -----        -------                       ------                        -------  -------------  ------
            [id]  n00tmeg   test_realm1  /C=BE/O=Test/OU=Test/CN=Test  /C=BE/O=Test/OU=Test/CN=Test                          inactive
            [id]  msfuser   test_realm2  /C=BE/O=Test/OU=Test/CN=Test  /C=BE/O=Test/OU=Test/CN=Test                          inactive
            Deactivated 2 entries
          TABLE
        end

        context 'with a username' do
          it 'should deactivate the matching Pkcs12 and show a single deactivated entry' do
            subject.cmd_certs('-A', 'n00tmeg')
            expect(table_without_ids(@output.join("\n"))).to match_table <<~TABLE
              Pkcs12
              ======
              id    username  realm        subject                       issuer                        ADCS CA  ADCS Template  status
              --    --------  -----        -------                       ------                        -------  -------------  ------
              [id]  n00tmeg   test_realm1  /C=BE/O=Test/OU=Test/CN=Test  /C=BE/O=Test/OU=Test/CN=Test                          inactive
              Deactivated 1 entry
            TABLE
          end
        end

        context 'with the -i option and an ID' do
          it 'should deactivate the matching Pkcs12 and show a single deactivated entry' do
            subject.cmd_certs('-A', '-i', "#{creds[1].id}")
            expect(table_without_ids(@output.join("\n"))).to match_table <<~TABLE
              Pkcs12
              ======
              id    username  realm        subject                       issuer                        ADCS CA  ADCS Template  status
              --    --------  -----        -------                       ------                        -------  -------------  ------
              [id]  msfuser   test_realm2  /C=BE/O=Test/OU=Test/CN=Test  /C=BE/O=Test/OU=Test/CN=Test                          inactive
              Deactivated 1 entry
            TABLE
          end
        end
      end

      context 'with a deactivated Pkcs12' do
        before :each do
          creds << FactoryBot.create(
            :metasploit_credential_core,
            public: FactoryBot.create(:metasploit_credential_username, username: username3),
            realm: FactoryBot.create(:metasploit_credential_realm, value: realm3),
            private: FactoryBot.create(:metasploit_credential_pkcs12_with_status, status: 'inactive'),
            origin: origin
          )
        end

        context 'when the -a option is provided' do
          it 'should activate the deactivated Pkcs12 and show all the activated entries' do
            subject.cmd_certs('-a')
            expect(table_without_ids(@output.join("\n"))).to match_table <<~TABLE
              Pkcs12
              ======
              id    username  realm        subject                       issuer                        ADCS CA  ADCS Template  status
              --    --------  -----        -------                       ------                        -------  -------------  ------
              [id]  n00tmeg   test_realm1  /C=BE/O=Test/OU=Test/CN=Test  /C=BE/O=Test/OU=Test/CN=Test                          active
              [id]  msfuser   test_realm2  /C=BE/O=Test/OU=Test/CN=Test  /C=BE/O=Test/OU=Test/CN=Test                          active
              [id]  msftest   test_realm3  /C=BE/O=Test/OU=Test/CN=Test  /C=BE/O=Test/OU=Test/CN=Test                          active
              Activated 3 entries
            TABLE
          end
        end

        context 'with a username' do
          it 'should activate the deactivated Pkcs12 and show the activated entry' do
            subject.cmd_certs('-a', 'msftest')
            expect(table_without_ids(@output.join("\n"))).to match_table <<~TABLE
              Pkcs12
              ======
              id    username  realm        subject                       issuer                        ADCS CA  ADCS Template  status
              --    --------  -----        -------                       ------                        -------  -------------  ------
              [id]  msftest   test_realm3  /C=BE/O=Test/OU=Test/CN=Test  /C=BE/O=Test/OU=Test/CN=Test                          active
              Activated 1 entry
            TABLE
          end
        end

        context 'with the -i option and an ID' do
          it 'should activate the deactivated Pkcs12 and show the activated entry' do
            subject.cmd_certs('-a', '-i', "#{creds.last.id}")
            expect(table_without_ids(@output.join("\n"))).to match_table <<~TABLE
              Pkcs12
              ======
              id    username  realm        subject                       issuer                        ADCS CA  ADCS Template  status
              --    --------  -----        -------                       ------                        -------  -------------  ------
              [id]  msftest   test_realm3  /C=BE/O=Test/OU=Test/CN=Test  /C=BE/O=Test/OU=Test/CN=Test                          active
              Activated 1 entry
            TABLE
          end
        end
      end

      context 'when the -e option is provided' do
        context 'with a username that doesn\'t match any Pkcs12' do
          it 'should return an error message' do
            subject.cmd_certs('-e', 'path', 'non-existing-user')
            expect(@error.join("\n")).to eq('No mathing Pkcs12 entry to export')
          end
        end

        context 'with more than one matching Pkcs12' do
          it 'should return an error message' do
            subject.cmd_certs('-e', 'path')
            expect(@error.join("\n")).to eq('More than one mathing Pkcs12 entry found. Filter with `-i` and/or provide a username')
          end
        end

        context 'with one matching Pkcs12' do
          it 'should export the matching Pkcs12 to the provided path' do
            ::Tempfile.create do |file|
              subject.cmd_certs('-e', file.path, 'n00tmeg')
              expect(::File.binread(file.path)).to eq(Base64.strict_decode64(creds[0].private.data))
            end
          end
        end
      end

    end
  end
end
