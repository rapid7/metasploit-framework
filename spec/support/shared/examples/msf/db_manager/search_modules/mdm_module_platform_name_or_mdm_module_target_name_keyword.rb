shared_examples_for 'Msf::DBManager#search_modules Mdm::ModulePlatform#name or Mdm::ModuleTarget#name keyword' do |keyword|
	context "with #{keyword} keyword" do
		let(:search_string) do
			"#{keyword}:#{name}"
		end

		let!(:module_platform) do
			FactoryGirl.create(:mdm_module_platform)
		end

		let!(:module_target) do
			FactoryGirl.create(:mdm_module_target)
		end

		context 'with Mdm::ModulePlatform#name' do
			let(:name) do
				module_platform.name
			end

			it 'should find matching Mdm::ModulePlatform#name' do
				module_details.count.should > 0

				module_details.all? { |module_detail|
					module_detail.platforms.any? { |module_platform|
						module_platform.name == name
					}
				}.should be_true
			end
		end

		context 'with Mdm::ModuleTarget#name' do
			let(:name) do
				module_target.name
			end

			it 'should find matching Mdm::ModuleTarget#name' do
				module_details.count.should > 0

				module_details.all? { |module_detail|
					module_detail.targets.any? { |module_target|
						module_target.name == name
					}
				}.should be_true
			end
		end
	end
end