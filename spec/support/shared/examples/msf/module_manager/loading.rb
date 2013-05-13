shared_examples_for 'Msf::ModuleManager::Loading' do
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