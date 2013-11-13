require 'spec_helper'

describe Metasploit::Framework::Module::Class::Logging do
  subject(:base_instance) do
    base_class.new
  end

  let(:base_class) do
    described_class = self.described_class

    Class.new do
      include described_class
    end
  end

  context '#module_class_location' do
    include_context 'database seeds'

    subject(:module_class_location) do
      base_instance.module_class_location(module_class)
    end

    #
    # lets
    #

    let(:module_class) do
      FactoryGirl.build(
          :mdm_module_class,
          module_type: module_type,
          payload_type: payload_type
      )
    end

    #
    # Callbacks
    #

    around(:each) do |example|
      with_established_connection do
        example.run
      end
    end

    before(:each) do
      # validate to populate derived fields
      module_class.valid?
    end

    context 'with one ancestor' do
      let(:module_type) do
        FactoryGirl.generate :metasploit_model_module_type
      end

      let(:payload_type) do
        if module_type == 'payload'
          'single'
        else
          nil
        end
      end

      it 'should include Metasploit::Model::Module::Class#full_name' do
        module_class_location.should include(module_class.full_name)
      end

      it "should include singular 'module ancestor'" do
        module_class_location.should include(' module ancestor ')
      end

      it 'should include Metasploit::Model::Module::Ancestor#real_path' do
        module_class_location.should include(module_class.ancestors.first.real_path)
      end
    end

    context 'with two ancestors' do
      let(:module_type) do
        'payload'
      end

      let(:payload_type) do
        'staged'
      end

      it 'should include Metasploit::Model::Module::Class#full_name' do
        module_class_location.should include(module_class.full_name)
      end

      it "should include plural 'module ancestors'" do
        module_class_location.should include(' module ancestors ')
      end

      it 'should include Metasploit::Model::Module::Ancestor#real_path sentence' do
        real_paths = module_class.ancestors.map(&:real_path).sort
        module_class_location.should include("#{real_paths[0]} and #{real_paths[1]}")
      end
    end
  end
end