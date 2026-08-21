RSpec.shared_examples_for 'Msf::DBManager::Import::MetasploitFramework::Zip' do
  it { is_expected.to respond_to :import_msf_collateral }
  it { is_expected.to respond_to :import_msf_zip }

  describe '#import_msf_zip' do
    before(:each) do
      skip("Not supported with remote DB") if ENV['REMOTE_DB']
    end

    let(:controlled_tmpdir) { Dir.mktmpdir('msf-zip-import-test') }

    # Redirect Dir.tmpdir so import_msf_zip extracts into our controlled directory
    before(:each) do
      allow(Dir).to receive(:tmpdir).and_return(controlled_tmpdir)
    end

    after { FileUtils.rm_rf(controlled_tmpdir) }

    def create_msf_zip(path, entries)
      Zip::OutputStream.open(path) do |zos|
        entries.each do |name, content|
          zos.put_next_entry(name)
          zos.write(content)
        end
      end
    end

    def valid_msf_xml
      "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<MetasploitV5>\n</MetasploitV5>\n"
    end

    # Find the extraction directory created by import_msf_zip under our controlled tmpdir
    def find_extracted_dir
      Dir.glob(File.join(controlled_tmpdir, 'msf', 'imp_*', '*')).first
    end

    context 'with a valid MSF zip containing loot and task entries' do
      let(:zip_path) { File.join(controlled_tmpdir, 'test_export.zip') }

      before do
        create_msf_zip(zip_path, {
          'test_export.xml' => valid_msf_xml,
          'loot/file1.bin' => 'loot content here',
          'tasks/task1.log' => 'task log content'
        })
      end

      it 'extracts zip entries to the temporary directory' do
        begin
          framework.db.import_file(filename: zip_path)
        rescue Msf::DBImportError
          # Expected — our minimal XML passes detection but not full parsing
        end

        extracted_tmp = find_extracted_dir
        expect(extracted_tmp).not_to be_nil
        expect(File.exist?(File.join(extracted_tmp, 'test_export.xml'))).to be true
        expect(File.exist?(File.join(extracted_tmp, 'loot', 'file1.bin'))).to be true
        expect(File.exist?(File.join(extracted_tmp, 'tasks', 'task1.log'))).to be true
        expect(File.read(File.join(extracted_tmp, 'loot', 'file1.bin'))).to eq('loot content here')
      end
    end

    context 'with a zip containing path traversal entries' do
      let(:zip_path) { File.join(controlled_tmpdir, 'malicious.zip') }

      before do
        create_msf_zip(zip_path, {
          '../escaped/pwned.txt' => 'pwned',
          'legit.xml' => valid_msf_xml
        })
      end

      it 'does not extract traversal entries outside the extraction directory' do
        original_stderr = $stderr
        $stderr = StringIO.new
        begin
          framework.db.import_file(filename: zip_path)
        rescue => _e
          # Expected
        ensure
          $stderr = original_stderr
        end

        # The extraction dir is at controlled_tmpdir/msf/imp_XXXX/malicious/
        # A ../escaped entry would land at controlled_tmpdir/msf/imp_XXXX/escaped/
        # Verify no escaped/ directory was created alongside the extraction dir
        extracted_dir = find_extracted_dir
        expect(extracted_dir).not_to be_nil
        parent_of_extraction = File.dirname(extracted_dir)
        expect(Dir.exist?(File.join(parent_of_extraction, 'escaped'))).to be false
        expect(File.exist?(File.join(parent_of_extraction, 'escaped', 'pwned.txt'))).to be false

        # Also verify the traversal file didn't end up anywhere else in the controlled tmpdir
        expect(File.exist?(File.join(controlled_tmpdir, 'escaped', 'pwned.txt'))).to be false
      end
    end
  end
end
