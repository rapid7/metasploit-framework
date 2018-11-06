RSpec.describe Metasploit::Credential::Importer::Zip do

  include_context 'metasploit_credential_importer_zip_file'

  let(:workspace){FactoryBot.create(:mdm_workspace)}
  subject(:zip_importer){ FactoryBot.build :metasploit_credential_importer_zip, workspace: workspace }

  describe "validations" do
    DUMMY_ZIP_PATH = "/tmp/import-test-dummy.zip"

    context "when the zip file contains a keys directory and a manifest CSV" do
      it { is_expected.to be_valid }
    end

    context "when the zip file is not actually an archive" do
      let(:error) do
        I18n.translate!('activemodel.errors.models.metasploit/credential/importer/zip.attributes.input.malformed_archive')
      end

      before(:example) do
        File.open(DUMMY_ZIP_PATH, 'wb')
        zip_importer.input = File.open(DUMMY_ZIP_PATH, 'r')
      end

      after(:example) do
        FileUtils.rm(DUMMY_ZIP_PATH)
      end

      it { is_expected.not_to be_valid }

      it 'should show the proper error message' do
        zip_importer.valid?
        expect(zip_importer.errors[:input]).to include error
      end
    end

    context "when the zip file does not contain a manifest CSV" do
      let(:error) do
        I18n.translate!('activemodel.errors.models.metasploit/credential/importer/zip.attributes.input.missing_manifest')
      end

      before(:example) do
        zip_importer.input = FactoryBot.generate :metasploit_credential_importer_zip_file_without_manifest
      end

      it { is_expected.not_to be_valid }

      it 'should show the proper error message' do
        zip_importer.valid?
        expect(zip_importer.errors[:input]).to include error
      end
    end

  end

  describe "#import!" do
    it 'should create Public credential objects for the usernames described in the manifest file' do
      expect{zip_importer.import!}.to change{Metasploit::Credential::Private.count}.from(0).to(5)
    end
  end

  describe "zip constants" do
    it 'should have ZIP_HEADER_IDENTIFIER whose length corresponds to ZIP_HEADER_BYTE_LENGTH' do
      expect(Metasploit::Credential::Importer::Zip::ZIP_HEADER_IDENTIFIER.size).to eq(Metasploit::Credential::Importer::Zip::ZIP_HEADER_BYTE_LENGTH)
    end
  end
end