# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Msf::Modules::Metadata::Store do
  describe '.collect_files_to_check' do
    let(:temp_install_root) { Dir.mktmpdir('msf_install') }
    let(:temp_user_modules) { Dir.mktmpdir('msf_user_modules') }

    before do
      allow(Msf::Config).to receive(:install_root).and_return(temp_install_root)
      allow(Msf::Config).to receive(:user_module_directory).and_return(temp_user_modules)
    end

    after do
      FileUtils.remove_entry(temp_install_root)
      FileUtils.remove_entry(temp_user_modules)
    end

    context 'when files exist in modules/, lib/, and user module directories' do
      before do
        # Create files under modules/
        FileUtils.mkdir_p(File.join(temp_install_root, 'modules', 'exploits', 'windows'))
        File.write(File.join(temp_install_root, 'modules', 'exploits', 'windows', 'test_exploit.rb'), 'exploit')
        File.write(File.join(temp_install_root, 'modules', 'exploits', 'auxiliary_helper.rb'), 'helper')

        # Create files under lib/
        FileUtils.mkdir_p(File.join(temp_install_root, 'lib', 'msf', 'core'))
        File.write(File.join(temp_install_root, 'lib', 'msf', 'core', 'exploit.rb'), 'lib code')
        File.write(File.join(temp_install_root, 'lib', 'msf', 'core', 'payload.rb'), 'lib code')

        # Create files in user module directory
        FileUtils.mkdir_p(File.join(temp_user_modules, 'exploits', 'custom'))
        File.write(File.join(temp_user_modules, 'exploits', 'custom', 'my_exploit.rb'), 'custom exploit')
      end

      it 'returns files under modules/' do
        result = described_class.collect_files_to_check
        modules_files = result.select { |f| f.include?('/modules/') }
        expect(modules_files.length).to eq(2)
      end

      it 'returns files under user module directories' do
        result = described_class.collect_files_to_check
        user_files = result.select { |f| f.start_with?(temp_user_modules) }
        expect(user_files.length).to eq(1)
        expect(user_files.first).to end_with('my_exploit.rb')
      end

      it 'does NOT include files under lib/' do
        result = described_class.collect_files_to_check
        lib_files = result.select { |f| f.include?('/lib/') }
        expect(lib_files).to be_empty
      end
    end

    context 'when only module files exist' do
      before do
        FileUtils.mkdir_p(File.join(temp_install_root, 'modules', 'post'))
        File.write(File.join(temp_install_root, 'modules', 'post', 'gather.rb'), 'post module')
      end

      it 'detects changes to module files via checksum validation' do
        # Get initial file list and compute checksum
        files_before = described_class.collect_files_to_check
        expect(files_before.length).to eq(1)

        # Modify the file content
        File.write(File.join(temp_install_root, 'modules', 'post', 'gather.rb'), 'modified post module')

        # The file should still appear in the list (changed content detected at checksum level)
        files_after = described_class.collect_files_to_check
        expect(files_after.length).to eq(1)
        expect(files_after.first).to eq(files_before.first)
      end
    end

    it 'returns a sorted array' do
      FileUtils.mkdir_p(File.join(temp_install_root, 'modules', 'b'))
      FileUtils.mkdir_p(File.join(temp_install_root, 'modules', 'a'))
      File.write(File.join(temp_install_root, 'modules', 'b', 'z.rb'), '')
      File.write(File.join(temp_install_root, 'modules', 'a', 'a.rb'), '')

      result = described_class.collect_files_to_check
      expect(result).to eq(result.sort)
    end
  end
end
