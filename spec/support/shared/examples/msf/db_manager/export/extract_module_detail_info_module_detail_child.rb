RSpec.shared_examples_for 'Msf::DBExport#extract_module_detail_info module_detail child' do |child_node_name|
  attribute_name = child_node_name.underscore

  subject(:child_node) do
    module_detail_node.at_xpath(child_node_name)
  end

  let(:attribute) do
    module_detail.send(attribute_name)
  end

  it "should not have Mdm::Module::Detail##{attribute_name} nil" do
    expect(attribute).not_to be_nil
  end

  it "should have Mdm::Module::Detail##{attribute_name} for #{child_node_name} content" do
    if attribute == false
      expect(child_node.content).to be_blank
    else
      expect(child_node.content).to eq attribute.to_s
    end
  end
end
