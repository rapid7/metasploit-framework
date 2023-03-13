RSpec.shared_examples_for 'a module with valid metadata' do
  valid_stability_values = Msf::ACCEPTABLE_STABILITY_TRAITS
  valid_side_effect_values = Msf::ACCEPTABLE_SIDE_EFFECT_TRAITS
  valid_reliability_values = Msf::ACCEPTABLE_RELIABILITY_TRAITS

  describe '#stability' do
    it 'has valid Stability notes values' do
      expect(subject.stability).to be_kind_of(Array)

      expect(valid_stability_values).to include(*subject.stability)
    end

    it 'cannot have an excellent module ranking unless it has a stability rating of crash safe' do
      if subject.rank_to_s == 'excellent' && subject.stability.empty?
        expect(subject.stability).to include('crash-safe')
      end
    end

    it 'cannot have an excellent module ranking unless it has a stability rating of crash safe' do
      if subject.rank_to_s == 'excellent' && !subject.stability.empty?
        expect(subject.stability).to include('crash-safe')
      end
    end
  end


  describe '#side_effects' do
    it 'has valid Side Effect notes values' do
      #
      # Checks if Side Effect values are valid
      #
      expect(subject.side_effects).to be_kind_of(Array)

      expect(valid_side_effect_values).to include(*subject.side_effects)
    end
  end

  describe '#reliability' do
    it 'has valid Reliability notes values' do
      #
      # Checks if Stability values are valid
      #
      expect(subject.reliability).to be_kind_of(Array)

      expect(valid_reliability_values).to include(*subject.reliability)
    end
  end
end

RSpec.shared_examples_for 'module notes are valid for' do |options = {}|
  options.assert_valid_keys(:module_type, :modules_pathname, :type_directory)

  module_type = options.fetch(:module_type)
  modules_pathname = options.fetch(:modules_pathname)
  modules_path = modules_pathname.to_path
  type_directory = options.fetch(:type_directory)

  include_context 'Msf::Simple::Framework#modules loading'

  context module_type do
    type_pathname = modules_pathname.join(type_directory)
    module_extension = '.rb'
    module_extension_regexp = /#{Regexp.escape(module_extension)}$/

    Dir.glob(type_pathname.join('**', "*#{module_extension}")) do |module_path|
      unless File.executable? module_path
        module_pathname = Pathname.new(module_path)
        module_reference_pathname = module_pathname.relative_path_from(type_pathname)
        module_reference_name = module_reference_pathname.to_path.gsub(module_extension_regexp, '')

        context module_reference_name do
          let(:module_instance) do
            load_and_create_module(
              module_type: module_type,
              modules_path: modules_path,
              reference_name: module_reference_name
            )
          end

          before(:each) do
            if module_instance.notes.empty?
              skip "#{module_reference_name}: Skipping as the module has no notes section"
            end
          end

          it_behaves_like 'a module with valid metadata' do
            subject { module_instance }
          end
        end
      end
    end
  end
end

RSpec.describe 'module' do
  modules_pathname = Pathname.new(__FILE__).parent.parent.join('modules')
  #
  # Verifies all modules notes are valid
  #
  context 'auxiliary' do
    # it should instantiate

    it_should_behave_like 'module notes are valid for',
                          module_type: 'auxiliary',
                          modules_pathname: modules_pathname,
                          type_directory: 'auxiliary'

  end

  context 'encoder' do
    it_should_behave_like 'module notes are valid for',
                          module_type: 'encoder',
                          modules_pathname: modules_pathname,
                          type_directory: 'encoders'
  end

  context 'exploit' do
    it_should_behave_like 'module notes are valid for',
                          module_type: 'exploit',
                          modules_pathname: modules_pathname,
                          type_directory: 'exploits'
  end

  context 'nops' do
    it_should_behave_like 'module notes are valid for',
                          module_type: 'nop',
                          modules_pathname: modules_pathname,
                          type_directory: 'nops'
  end

  context 'post' do
    it_should_behave_like 'module notes are valid for',
                          module_type: 'post',
                          modules_pathname: modules_pathname,
                          type_directory: 'posts'
  end
end
