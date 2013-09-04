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

		context 'with directory' do
			it 'should add path to #module_paths' do
				Dir.mktmpdir do |path|
					module_manager.add_path(path)

					module_paths.should include(path)
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