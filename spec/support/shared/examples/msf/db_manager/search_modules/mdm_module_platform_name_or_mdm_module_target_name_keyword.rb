RSpec.shared_examples_for 'Msf::DBManager#search_modules Mdm::Module::Platform#name or Mdm::Module::Target#name keyword' do |keyword|
  context "with #{keyword} keyword" do
    let(:search_string) do
      "#{keyword}:#{name}"
    end

    let!(:module_platform) do
      FactoryBot.create(:mdm_module_platform)
    end

    let!(:module_target) do
      FactoryBot.create(:mdm_module_target)
    end

    context 'with Mdm::Module::Platform#name' do
      let(:name) do
        # use inspect to quote spaces in string
        module_platform.name.inspect
      end

      it 'should find matching Mdm::Module::Platform#name' do
        expect(module_details.count).to be > 0

        expect(
          module_details.all? { |module_detail|
            module_detail.platforms.any? { |module_platform|
              module_platform.name == self.module_platform.name
            }
          }
        ).to eq true
      end
    end

    context 'with Mdm::Module::Target#name' do
      let(:name) do
        # use inspect to quote spaces in string
        module_target.name.inspect
      end

      it 'should find matching Mdm::Module::Target#name' do
        expect(module_details.count).to be > 0

        expect(
          module_details.all? { |module_detail|
            module_detail.targets.any? { |module_target|
              module_target.name == self.module_target.name
            }
          }
        ).to eq true
      end
    end
  end
end
