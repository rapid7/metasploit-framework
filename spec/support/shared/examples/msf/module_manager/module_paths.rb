shared_examples_for 'Msf::ModuleManager::ModulePaths' do
	def module_paths
		module_manager.send(:module_paths)
	end

	context '#add_path' do
		it 'should strip trailing File::SEPARATOR from the path' do
			Dir.mktmpdir do |path|
				path_with_trailing_separator = path + File::SEPARATOR
				module_manager.add_path(path_with_trailing_separator)

				module_paths.should_not include(path_with_trailing_separator)
				module_paths.should include(path)
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
					module_manager.add_path(path)
				}.to raise_error(ArgumentError, "The path supplied does not exist")
			end

			it 'should add the path to #module_paths if the File exists' do
				Tempfile.open(archive_basename) do |temporary_file|
					path = temporary_file.path

					File.exist?(path).should be_true

					module_manager.add_path(path)

					module_paths.should include(path)
				end
			end
		end

		context 'with directory' do
			it 'should add path to #module_paths' do
				Dir.mktmpdir do |path|
					module_manager.add_path(path)

					module_paths.should include(path)
				end
			end

			context 'containing Fastlib archives' do
				it 'should add each Fastlib archive to #module_paths' do
					Dir.mktmpdir do |directory|
						Tempfile.open(archive_basename, directory) do |file|
							module_manager.add_path(directory)

							module_paths.should include(directory)
							module_paths.should include(file.path)
						end
					end
				end
			end
		end

		context 'with other file' do
			it 'should raise ArgumentError' do
				Tempfile.open(basename_prefix) do |file|
					expect {
						subject.add_path(file.path)
					}.to raise_error(ArgumentError, 'The path supplied is not a valid directory.')
				end
			end
		end
	end
end