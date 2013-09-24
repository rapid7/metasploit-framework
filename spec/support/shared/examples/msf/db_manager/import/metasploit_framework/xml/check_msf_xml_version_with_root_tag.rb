# -*- coding:binary -*-
shared_examples_for 'Msf::DBManager::Import::MetasploitFramework::XML#check_msf_xml_version! with root tag' do |root_tag, options={}|
	options.assert_valid_keys(:allow_yaml)
	allow_yaml = options.fetch(:allow_yaml)

	context "with #{root_tag}" do
		let(:root_tag) do
			root_tag
		end

		should_label_by_allow_yaml = {
				true => 'should',
				false => 'should not'
		}
		should_label = should_label_by_allow_yaml[allow_yaml]

		it "#{should_label} allow YAML" do
			expect(metadata[:allow_yaml]).to eq(allow_yaml)
		end

		it "should have #{root_tag} as root tag" do
			metadata[:root_tag].should == root_tag
		end
	end
end
