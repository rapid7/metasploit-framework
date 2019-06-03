RSpec.shared_examples_for 'Msf::DBManager#search_modules Mdm::Module::Ref#name keyword' do |keyword|
  context "with #{keyword} keyword" do
    let(keyword) do
      1
    end

    let(:name) do
      FactoryBot.generate :mdm_module_ref_name
    end

    let(:search_string) do
      "#{keyword}:#{send(keyword)}"
    end

    before(:example) do
      FactoryBot.create(:mdm_module_ref, :name => name)
    end

    name_prefix = "#{keyword.to_s.upcase}-"
    context_suffix = "Mdm::Module::Ref#name starting with #{name_prefix.inspect}"

    context "with #{context_suffix}" do
      let(:name) do
        "#{name_prefix}#{send(keyword)}"
      end

      it 'should match Mdm::Module::Ref#name' do
        expect(module_details.count).to be > 0

        expect(
          module_details.all? { |module_detail|
            module_detail.refs.any? { |module_ref|
              module_ref.name == name
            }
          }
        ).to eq true
      end
    end

    context "without #{context_suffix}" do
      it 'should not match Mdm::Module::Ref#name' do
        expect(module_details.count).to eq 0
      end
    end
  end
end
