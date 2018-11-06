RSpec.describe Metasploit::Credential::Importer::Core do

  let(:workspace){FactoryBot.create(:mdm_workspace)}

  subject(:core_csv_importer){FactoryBot.build(:metasploit_credential_core_importer, workspace:workspace)}

  # CSV objects are IOs
  after(:example) do
    core_csv_importer.csv_object.rewind
  end

  describe "validations" do
    describe "short-form imports" do
      describe "with well-formed CSV data" do
        before(:example) do
          core_csv_importer.input = FactoryBot.generate :short_well_formed_csv
          core_csv_importer.private_credential_type = "Metasploit::Credential::Password"
        end

        it { is_expected.to be_valid }
      end

      describe "with a non-supported credential type" do
        let(:error) do
          I18n.translate!('activemodel.errors.models.metasploit/credential/importer/core.attributes.private_credential_type.invalid_type')
        end

        before(:example) do
          core_csv_importer.input = FactoryBot.generate :short_well_formed_csv
          core_csv_importer.private_credential_type = "Metasploit::Credential::SSHKey"
        end

        it{ is_expected.not_to be_valid }

        it 'should report the error being invalid private type' do
          core_csv_importer.valid?
          expect(core_csv_importer.errors[:private_credential_type]).to include error
        end
      end

      describe "with non-compliant headers" do
        let(:error) do
          I18n.translate!('activemodel.errors.models.metasploit/credential/importer/core.attributes.input.incorrect_csv_headers')
        end

        before(:example) do
          core_csv_importer.input = FactoryBot.generate :short_well_formed_csv_non_compliant_header
          core_csv_importer.private_credential_type = "Metasploit::Credential::Password"
        end

        it{ is_expected.not_to be_valid }

        it 'should report the error being invalid headers' do
          core_csv_importer.valid?
          expect(core_csv_importer.errors[:input]).to include error
        end
      end
    end

    describe "long-form imports" do
      describe "with well-formed CSV data" do
        describe "with a compliant header" do
          it { is_expected.to be_valid }
        end

        describe "with data that includes a missing Public (username)" do
          before(:example) do
            core_csv_importer.input = FactoryBot.generate :well_formed_csv_compliant_header_missing_public
          end

          it 'should create a new Metasploit::Credential::Username for each unique Public in the import' do
            expect{ core_csv_importer.import! }.to change(Metasploit::Credential::Username, :count).from(0).to(2)
          end
        end

        describe "with data that includes a missing Private" do
          before(:example) do
            core_csv_importer.input = FactoryBot.generate :well_formed_csv_compliant_header_missing_private
          end

          it 'should create a new Metasploit::Credential::Private for each unique Private in the import' do
            expect{ core_csv_importer.import! }.to change(Metasploit::Credential::Private, :count).from(0).to(2)
          end
        end

        describe "with data that describes duplicate Cores" do
          let(:preexisting_cred_data) do
            core_csv_importer.csv_object.gets
            row = core_csv_importer.csv_object.first
            core_csv_importer.csv_object.rewind
            {
              username: row['username'],
              private_data: row['private_data'],
              realm_key: row['realm_key'],
              realm_value: row['realm_value'],
            }
          end

          before(:example) do
            core         = Metasploit::Credential::Core.new
            core.public  = FactoryBot.create(:metasploit_credential_username, username: preexisting_cred_data[:username])
            core.private = FactoryBot.create(:metasploit_credential_password, data: preexisting_cred_data[:private_data])
            core.realm   = FactoryBot.create(:metasploit_credential_realm, key: preexisting_cred_data[:realm_key],
                                                                            value: preexisting_cred_data[:realm_value])
            core.origin    = FactoryBot.create(:metasploit_credential_origin_import)
            core.workspace = workspace
            core.save!
          end

          it 'should create a new Metasploit::Credential::Core for each unique row in the import' do
            expect{core_csv_importer.import!}.to change(Metasploit::Credential::Core, :count).from(1).to(3)
          end
        end

        describe "with a non-compliant header" do
          let(:error) do
            I18n.translate!('activemodel.errors.models.metasploit/credential/importer/core.attributes.input.incorrect_csv_headers')
          end

          before(:example) do
            core_csv_importer.input = FactoryBot.generate(:well_formed_csv_non_compliant_header)
          end

          it { is_expected.not_to be_valid }

          it 'should report the error being incorrect headers' do
            core_csv_importer.valid?
            expect(core_csv_importer.errors[:input]).to include error
          end
        end

        describe "with a malformed CSV" do
          let(:error) do
            I18n.translate!('activemodel.errors.models.metasploit/credential/importer/core.attributes.input.malformed_csv')
          end

          before(:example) do
            core_csv_importer.input = FactoryBot.generate(:malformed_csv)
          end

          it { is_expected.to be_invalid }

          it 'should report the error being malformed CSV' do
            core_csv_importer.valid?
            expect(core_csv_importer.errors[:input]).to include error
          end
        end

        describe "with an empty CSV" do
          let(:error) do
            I18n.translate!('activemodel.errors.models.metasploit/credential/importer/core.attributes.input.empty_csv')
          end

          before(:example) do
            core_csv_importer.input = FactoryBot.generate(:empty_core_csv)
          end

          it { is_expected.to be_invalid }

          it 'should show the proper error message' do
            core_csv_importer.valid?
            expect(core_csv_importer.errors[:input]).to include error
          end
        end

        describe "when accesssing without rewind" do
          before(:example) do
            core_csv_importer.csv_object.gets
          end

          it 'should raise a runtime error when attempting to validate' do
            expect{ core_csv_importer.valid? }.to raise_error(RuntimeError)
          end
        end
      end
    end

    describe "short-form imports" do
      before(:example) do
        core_csv_importer.private_credential_type = "Metasploit::Credential::Password"
        core_csv_importer.input = FactoryBot.generate :short_well_formed_csv
      end

      describe "when the data in the CSV is all new" do
        it 'should create new Metasploit::Credential::Username for that row' do
          expect{ core_csv_importer.import! }.to change(Metasploit::Credential::Username, :count).from(0).to(2)
        end

        it 'should create new Metasploit::Credential::Private for that row' do
          expect{ core_csv_importer.import! }.to change(Metasploit::Credential::Password, :count).from(0).to(2)
        end
      end

      describe "when the data in the CSV contains duplicates" do
        let(:preexisting_cred_data) do
          core_csv_importer.csv_object.gets
          row = core_csv_importer.csv_object.first
          core_csv_importer.csv_object.rewind
          {
            username: row['username'],
            private_data: row['private_data'],
          }
        end

        before(:example) do
          core         = Metasploit::Credential::Core.new
          core.public  = FactoryBot.create(:metasploit_credential_username, username: preexisting_cred_data[:username])
          core.private = FactoryBot.create(:metasploit_credential_password, data: preexisting_cred_data[:private_data])
          core.origin  = FactoryBot.create(:metasploit_credential_origin_import)
          core.workspace = workspace
          core.save!
        end

        it 'should create a new Metasploit::Credential::Core for each unique row in the import' do
          expect{core_csv_importer.import!}.to change(Metasploit::Credential::Core, :count).from(1).to(2)
        end
      end
    end
  end

  describe "#import!" do
    context "public" do
      context "when it is already in the DB" do
        # Contains 3 unique Publics
        let(:stored_public){ core_csv_importer.csv_object.gets; core_csv_importer.csv_object.first['username'] }

        before(:example) do
          Metasploit::Credential::Username.create!(username: stored_public)
          core_csv_importer.csv_object.rewind
        end

        it 'should not create a new Metasploit::Credential::Username for that object' do
          expect{ core_csv_importer.import! }.to change(Metasploit::Credential::Username, :count).from(1).to(3)
        end
      end

      context "when it is not in the DB" do
        it 'should create a new Metasploit::Credential::Username for each unique Public in the import' do
          expect{ core_csv_importer.import! }.to change(Metasploit::Credential::Username, :count).from(0).to(3)
        end
      end
    end

    context "private" do
      context "when it is already in the DB" do
        # Contains 3 unique Privates
        let(:stored_private_row){ core_csv_importer.csv_object.gets; core_csv_importer.csv_object.first }
        let(:private_class){ stored_private_row['private_type'].constantize }

        before(:example) do
          private_cred      = private_class.new
          private_cred.data = stored_private_row['private_data']
          private_cred.save!
          core_csv_importer.csv_object.rewind
        end

        it 'should not create a new Metasploit::Credential::Private for that object' do
          expect{ core_csv_importer.import! }.to change(Metasploit::Credential::Private, :count).from(1).to(3)
        end

      end

      context "when it is not in the DB" do
        it 'should create a new Metasploit::Credential::Private for each unique Private in the import' do
          expect{ core_csv_importer.import! }.to change(Metasploit::Credential::Private, :count).from(0).to(3)
        end
      end
    end

    context "realm" do
      context "when it is already in the DB" do
        # Contains 2 unique Realms
        let(:stored_realm_row){ core_csv_importer.csv_object.gets; core_csv_importer.csv_object.first }

        before(:example) do
          Metasploit::Credential::Realm.create(key: stored_realm_row['realm_key'],
                                               value: stored_realm_row['realm_value'])
        end

        it 'should create only Realms that do not exist in the DB' do
          expect{ core_csv_importer.import! }.to change(Metasploit::Credential::Realm, :count).from(1).to(2)
        end
      end

      context "when it is not in the DB" do
        it 'should create only Realms that do not exist in the DB' do
          expect{ core_csv_importer.import! }.to change(Metasploit::Credential::Realm, :count).from(0).to(2)
        end
      end
    end

    context "core" do
      it 'should create a Core object for each row in the DB' do
        expect{ core_csv_importer.import! }.to change(Metasploit::Credential::Core, :count).from(0).to(3)
      end
    end

    context "when there are Logins in the input" do
      before(:example) do
        core_csv_importer.input = FactoryBot.generate :well_formed_csv_compliant_header_with_service_info
      end

      it 'should create Logins' do
        expect{core_csv_importer.import!}.to change(Metasploit::Credential::Login, :count).from(0).to(2)
      end

      it 'should create Mdm::Host objects' do
        expect{core_csv_importer.import!}.to change(Mdm::Host, :count).from(0).to(2)
      end

      it 'should create Mdm::Service objects' do
        expect{core_csv_importer.import!}.to change(Mdm::Service, :count).from(0).to(2)
      end
    end
  end

end
