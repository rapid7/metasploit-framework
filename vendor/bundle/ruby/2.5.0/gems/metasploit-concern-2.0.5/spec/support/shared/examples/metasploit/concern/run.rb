RSpec.shared_examples_for 'Metasploit::Concern.run' do
  let(:load_hook_name) {
    described_class.name.underscore.gsub('/', '_').to_sym
  }

  let(:loaded_bases_by_name) {
    ActiveSupport.module_eval { @loaded }
  }

  context 'with correct base' do
    it 'calls ActiveSupport.run_load_hooks with correct load hook name' do
      actual_names = []

      loaded_bases_by_name.each do |name, bases|
        bases.each do |base|
          if base == described_class
            actual_names << name
            break
          end
        end
      end

      expect(actual_names).to include(load_hook_name)
    end
  end

  context 'with correct load hook name' do
    it 'calls ActiveSupport.run_load_hooks with correct base' do
      actual_bases = loaded_bases_by_name[load_hook_name]

      expect(actual_bases).to include(described_class)
    end
  end
end