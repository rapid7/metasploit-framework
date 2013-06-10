shared_examples_for 'Msf::DBManager#search_modules Mdm::Module::Platform#name or Mdm::Module::Target#name keyword' do |keyword|
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

		context 'with Mdm::Module::Platform#name' do
			let(:name) do
				# use inspect to quote spaces in string
				module_platform.name.inspect
			end

			it 'should find matching Mdm::Module::Platform#name' do
				module_details.count.should > 0

				module_details.all? { |module_detail|
					module_detail.platforms.any? { |module_platform|
						module_platform.name == self.module_platform.name
					}
				}.should be_true
			end
		end

		context 'with Mdm::Module::Target#name' do
			let(:name) do
 				# use inspect to quote spaces in string
				module_target.name.inspect
			end

			it 'should find matching Mdm::Module::Target#name' do
				module_details.count.should > 0

				module_details.all? { |module_detail|
					module_detail.targets.any? { |module_target|
						module_target.name == self.module_target.name
					}
				}.should be_true
			end
		end
	end
end