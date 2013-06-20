shared_examples_for 'Msf::DBManager::Export#extract_module_detail_info module_detail child' do |child_node_name|
	attribute_name = child_node_name.underscore

	subject(:child_node) do
		module_detail_node.at_xpath(child_node_name)
	end

	let(:attribute) do
		module_detail.send(attribute_name)
	end

	it "should not have Mdm::Module::Detail##{attribute_name} nil" do
	  attribute.should_not be_nil
	end

	it "should have Mdm::Module::Detail##{attribute_name} for #{child_node_name} content" do
		if attribute == false
			child_node.content.should be_blank
		else
			child_node.content.should == attribute.to_s
		end
	end
end