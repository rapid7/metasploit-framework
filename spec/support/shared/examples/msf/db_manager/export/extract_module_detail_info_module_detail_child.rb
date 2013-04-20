shared_examples_for 'Msf::DBManager::Export#extract_module_detail_info module_detail child' do |child_node_name|
	attribute_name = child_node_name.underscore

	subject(:child_node) do
		module_detail_node.at_xpath(child_node_name)
	end

	let(:attribute) do
		module_detail.send(attribute_name)
	end

	it "should have Mdm::ModuleDetail##{attribute_name} present" do
	  attribute.should be_present
	end

	it "should have Mdm::ModuleDetail##{attribute_name} for #{child_node_name} content" do
		child_node.content.should == attribute.to_s
	end
end