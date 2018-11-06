RSpec.describe Metasploit::Credential::Importer::Multi do

  include_context 'metasploit_credential_importer_zip_file'

  UNSUPPORTED_FILE = 'bad.txt'
  INVALID_CSV_FILE = 'malformed.csv'
  VALID_CSV_FILE   = 'well-formed.csv'

  let(:import_origin){ FactoryBot.create :metasploit_credential_origin_import }
  let(:supported_file){ FactoryBot.generate :metasploit_credential_importer_zip_file }
  let(:unsupported_file){ File.open("#{Dir.tmpdir}/#{UNSUPPORTED_FILE}", 'wb') }

  let(:invalid_csv){ FactoryBot.generate(:malformed_csv)}
  let(:valid_csv){ FactoryBot.generate(:well_formed_csv_compliant_header)}

  let(:valid_csv_file) do
    File.open("#{Dir.tmpdir}/#{VALID_CSV_FILE}", 'w') do |file|
      file << valid_csv.read
    end
  end

  describe "validation" do
    describe "when given a file that is not a zip or a CSV" do
      subject(:multi_importer){ Metasploit::Credential::Importer::Multi.new(input: File.open(unsupported_file), origin: import_origin)}

      it { is_expected.not_to be_valid }
    end

    context "when given zip file" do
      subject(:multi_importer){ Metasploit::Credential::Importer::Multi.new(input: File.open(supported_file), origin: import_origin)}

      it { is_expected.to be_valid }
    end

    describe "#csv?" do
      describe 'when the file can be opened as a CSV' do
        subject(:multi_importer){ Metasploit::Credential::Importer::Multi.new(input: File.open(valid_csv_file), origin: import_origin)}

        it 'should return true' do
          expect(multi_importer.csv?).to eq(true)
        end
      end

      describe 'when the file is not a well-formed CSV' do
        subject(:multi_importer){ Metasploit::Credential::Importer::Multi.new(input: File.open(unsupported_file), origin: import_origin)}

        it 'should return true' do
          expect(multi_importer.csv?).to eq(false)
        end
      end
    end
  end
end