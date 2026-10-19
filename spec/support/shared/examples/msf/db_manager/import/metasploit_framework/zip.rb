RSpec.shared_examples_for 'Msf::DBManager::Import::MetasploitFramework::Zip' do
  it { is_expected.to respond_to :import_msf_collateral }
  it { is_expected.to respond_to :import_msf_zip }

  describe '#resolve_zip_import_path' do
    let(:zip_tmp) { Dir.mktmpdir('msf-zip-path-test') }

    after { FileUtils.rm_rf(zip_tmp) }

    it 'resolves a regular file within the ZIP extraction directory' do
      loot_path = File.join(zip_tmp, 'loot', 'example.txt')
      FileUtils.mkdir_p(File.dirname(loot_path))
      File.write(loot_path, 'example')

      expect(subject.resolve_zip_import_path(zip_tmp, './loot/example.txt')).to eq(loot_path)
    end

    it 'rejects an absolute path outside the ZIP extraction directory' do
      external_file = Tempfile.new('msf-zip-external-file')

      expect do
        subject.resolve_zip_import_path(zip_tmp, external_file.path)
      end.to raise_error(Msf::DBImportError, /escapes the ZIP extraction directory/)
    ensure
      external_file&.close!
    end

    it 'rejects a path that traverses outside the ZIP extraction directory' do
      external_path = File.join(File.dirname(zip_tmp), 'external.txt')
      File.write(external_path, 'external')

      expect do
        subject.resolve_zip_import_path(zip_tmp, '../external.txt')
      end.to raise_error(Msf::DBImportError, /escapes the ZIP extraction directory/)
    ensure
      FileUtils.rm_f(external_path)
    end

    it 'rejects symbolic links' do
      external_file = Tempfile.new('msf-zip-symlink-target')
      symlink_path = File.join(zip_tmp, 'loot-link')
      File.symlink(external_file.path, symlink_path)

      expect do
        subject.resolve_zip_import_path(zip_tmp, './loot-link')
      end.to raise_error(Msf::DBImportError, /contains a symbolic link/)
    ensure
      external_file&.close!
    end

    it 'rejects a symbolic link used as the ZIP extraction directory' do
      actual_zip_tmp = Dir.mktmpdir('msf-zip-symlink-root-target')
      symlink_zip_tmp = "#{actual_zip_tmp}-link"
      File.symlink(actual_zip_tmp, symlink_zip_tmp)

      expect do
        subject.resolve_zip_import_path(symlink_zip_tmp, './loot/example.txt')
      end.to raise_error(Msf::DBImportError, /ZIP extraction directory is not a regular directory/)
    ensure
      FileUtils.rm_f(symlink_zip_tmp)
      FileUtils.rm_rf(actual_zip_tmp)
    end
  end

  it 'skips a missing file within the ZIP extraction directory' do
    zip_tmp = Dir.mktmpdir('msf-zip-missing-file-test')

    expect(subject.resolve_zip_import_path(zip_tmp, './loot/missing.txt')).to be_nil
  ensure
    FileUtils.rm_rf(zip_tmp)
  end

  describe '#is_child_of?' do
    it 'rejects a sibling path with a common prefix' do
      expect(subject.is_child_of?('/tmp/import', '/tmp/import-other/file')).to be false
    end

    it 'compares paths case-insensitively on Windows' do
      allow(Gem).to receive(:win_platform?).and_return(true)

      expect(subject.is_child_of?('/tmp/Import', '/tmp/import/file')).to be true
    end
  end

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
      Dir.glob(File.join(controlled_tmpdir, 'msf-zip-import-*')).first
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
        expect(File.stat(extracted_tmp).mode & 0o777).to eq(0o700)
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
        rescue StandardError => _e
          # Expected
        ensure
          $stderr = original_stderr
        end

        # The extraction dir is at controlled_tmpdir/msf-zip-import-XXXX.
        # A ../escaped entry would land at controlled_tmpdir/escaped/.
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
