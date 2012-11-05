require 'spec_helper'

#
# Core
#

# Temporary files
require 'tempfile'
# add mktmpdir to Dir
require 'tmpdir'

#
# Project
#

require 'msf/core'

describe Msf::ModuleManager do
  let(:archive_basename) do
    [basename_prefix, archive_extension]
  end

  let(:archive_extension) do
    '.fastlib'
  end

  let(:basename_prefix) do
    'rspec'
  end

  let(:framework) do
    Msf::Framework.new
  end

  subject do
    described_class.new(framework)
  end

  context '#add_module_path' do
    it 'should strip trailing File::SEPARATOR from the path' do
      Dir.mktmpdir do |path|
        path_with_trailing_separator = path + File::SEPARATOR
        subject.add_module_path(path_with_trailing_separator)

        subject.send(:module_paths).should_not include(path_with_trailing_separator)
        subject.send(:module_paths).should include(path)
      end
    end

    context 'with Fastlib archive' do
      it 'should raise an ArgumentError unless the File exists' do
        file = Tempfile.new(archive_basename)
        # unlink will clear path, so copy it to a variable
        path = file.path
        file.unlink

        File.exist?(path).should be_false

        expect {
          subject.add_module_path(path)
        }.to raise_error(ArgumentError, "The path supplied does not exist")
      end

      it 'should add the path to #module_paths if the File exists' do
        Tempfile.open(archive_basename) do |temporary_file|
          path = temporary_file.path

          File.exist?(path).should be_true

          subject.add_module_path(path)

          subject.send(:module_paths).should include(path)
        end
      end
    end

    context 'with directory' do
      it 'should add path to #module_paths' do
        Dir.mktmpdir do |path|
          subject.add_module_path(path)

          subject.send(:module_paths).should include(path)
        end
      end

      context 'containing Fastlib archives' do
        it 'should add each Fastlib archive to #module_paths' do
          Dir.mktmpdir do |directory|
            Tempfile.open(archive_basename, directory) do |file|
              subject.add_module_path(directory)

              subject.send(:module_paths).should include(directory)
              subject.send(:module_paths).should include(file.path)
            end
          end
        end
      end
    end

    context 'with other file' do
      it 'should raise ArgumentError' do
        Tempfile.open(basename_prefix) do |file|
          expect {
            subject.add_module_path(file.path)
          }.to raise_error(ArgumentError, 'The path supplied is not a valid directory.')
        end
      end
    end
  end

	context '#file_changed?' do
		let(:module_basename) do
			[basename_prefix, '.rb']
		end

		it 'should return true if module info is not cached' do
			Tempfile.open(module_basename) do |tempfile|
				module_path = tempfile.path

				subject.send(:module_info_by_path)[module_path].should be_nil
				subject.file_changed?(module_path).should be_true
			end
		end

		it 'should return true if the cached type is Msf::MODULE_PAYLOAD' do
			Tempfile.open(module_basename) do |tempfile|
				module_path = tempfile.path
				modification_time = File.mtime(module_path)

				subject.send(:module_info_by_path)[module_path] = {
						# :modification_time must match so that it is the :type that is causing the `true` and not the
						# :modification_time causing the `true`.
						:modification_time => modification_time,
				    :type => Msf::MODULE_PAYLOAD
				}

				subject.file_changed?(module_path).should be_true
			end
		end

		context 'with cache module info and not a payload module' do
			it 'should return true if the file does not exist on the file system' do
				tempfile = Tempfile.new(module_basename)
				module_path = tempfile.path
				modification_time = File.mtime(module_path).to_i

				subject.send(:module_info_by_path)[module_path] = {
						:modification_time => modification_time
				}

				tempfile.unlink

				File.exist?(module_path).should be_false
				subject.file_changed?(module_path).should be_true
			end

			it 'should return true if modification time does not match the cached modification time' do
				Tempfile.open(module_basename) do |tempfile|
					module_path = tempfile.path
					modification_time = File.mtime(module_path).to_i
					cached_modification_time = (modification_time * rand).to_i

					subject.send(:module_info_by_path)[module_path] = {
							:modification_time => cached_modification_time
					}

					cached_modification_time.should_not == modification_time
					subject.file_changed?(module_path).should be_true
				end
			end

			it 'should return false if modification time does match the cached modification time' do
				Tempfile.open(module_basename) do |tempfile|
					module_path = tempfile.path
					modification_time = File.mtime(module_path).to_i
					cached_modification_time = modification_time

					subject.send(:module_info_by_path)[module_path] = {
							:modification_time => cached_modification_time
					}

					cached_modification_time.should == modification_time
					subject.file_changed?(module_path).should be_false
				end
			end
		end
	end
end