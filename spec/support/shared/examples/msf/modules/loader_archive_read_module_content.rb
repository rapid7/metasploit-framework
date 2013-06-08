# -*- coding:binary -*-
shared_examples_for 'Msf::Modules::Loader::Archive#read_module_content' do
	it 'should be able to read the module content' do
		archived_module_content = subject.send(:read_module_content, @parent_path, type, module_reference_name)
		unarchived_module_content = ''

		File.open(unarchived_path) do |f|
			unarchived_module_content = f.read
		end

		unarchived_module_content.should_not be_empty
		archived_module_content.should == unarchived_module_content
	end
end
