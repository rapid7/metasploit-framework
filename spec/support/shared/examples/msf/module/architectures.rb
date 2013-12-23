shared_examples_for 'Msf::Module::Architectures' do
  context '#arch' do
    subject(:arch) do
      metasploit_instance.arch
    end

    it 'calls #architecture_abbreviations' do
      metasploit_instance.should_receive(:architecture_abbreviations)

      arch
    end
  end

  context '#arch?' do
    subject(:arch?) do
      metasploit_instance.arch?(architecture_abbreviation)
    end

    let(:architecture_abbreviation) do
      FactoryGirl.generate :metasploit_model_architecture_abbreviation
    end

    it 'calls #compatible_architecture_abbreviation?' do
      expect(metasploit_instance).to receive(:compatible_architecture_abbreviation?).with(architecture_abbreviation)

      arch?
    end
  end

  context '#architecture_abbreviations' do
    subject(:architecture_abbreviations) do
      metasploit_instance.architecture_abbreviations
    end

    it 'is memozied' do
      expected = double('#architecture_abbreviations')
      metasploit_instance.instance_variable_set :@architecture_abbreviations, expected

      expect(architecture_abbreviations).to eq(expected)
    end

    context "with 'Arch'" do
      let(:expected_architecture_abbreviations) do
        Metasploit::Model::Architecture::ABBREVIATIONS.sample(2)
      end

      let(:metasploit_instance) do
        described_class.new(
            'Arch' => expected_architecture_abbreviations
        )
      end

      it 'is Array<String>' do
        expect(architecture_abbreviations).to be_a Array

        expect(
            architecture_abbreviations.all? { |architecture_abbreviation|
              architecture_abbreviation.is_a? String
            }
        ).to be_true
      end

      it "is architecture abbreviation in 'Arch'" do
        expect(architecture_abbreviations).to match_array(expected_architecture_abbreviations)
      end
    end

    context "without 'Arch'" do
      include_context 'database cleaner'

      #
      # lets
      #

      let(:metasploit_class) do
        Class.new(described_class)
      end

      let(:metasploit_instance) do
        metasploit_class.new
      end

      let(:module_class) do
        FactoryGirl.create(:mdm_module_class)
      end

      #
      # Callbacks
      #

      before(:each) do
        metasploit_class.stub(module_class: module_class)
      end

      it "defaults to ['x86']" do
        expect(architecture_abbreviations).to match_array(['x86'])
      end

      it 'uses Metasploit::Framework::Module::Class::Logging#module_class_location for deprecation warning' do
        expected_location = metasploit_instance.module_class_location(module_class)
        # ensure that method isn't inlining location calculation
        expect(metasploit_instance).to receive(:module_class_location).with(module_class).and_call_original

        expect(ActiveSupport::Deprecation).to receive(:warn) do |message, _callstack|
          message.should include(expected_location)
        end

        architecture_abbreviations
      end

      it 'does not include callstack in ActiveSupport::Deprecation warning' do
        expect(ActiveSupport::Deprecation).to receive(:warn).with(
                                                  an_instance_of(String),
                                                  []
                                              )

        architecture_abbreviations
      end

      it 'warns that assuming x86 by default is deprecated' do
        expect(ActiveSupport::Deprecation).to receive(:warn) do |message, _callstack|
          expect(message).to include("Defaulting to ARCH_X86 when no 'Arch' is given is deprecated.")
          expect(message).to include("Add explicit `'Arch' => ARCH_X86` to info Hash")
        end

        architecture_abbreviations
      end
    end
  end

  context '#architecture_abbreviations_to_s' do
    subject(:architecture_abbreviations_to_s) do
      metasploit_instance.architecture_abbreviations_to_s
    end

    let(:architecture_abbreviations) do
      Metasploit::Model::Architecture::ABBREVIATIONS.sample(2)
    end

    #
    # Callbacks
    #

    before(:each) do
      metasploit_instance.architecture_abbreviations = architecture_abbreviations
    end

    it 'is comma separated list of architecture abbreviations' do
      sorted = architecture_abbreviations.sort

      expect(architecture_abbreviations_to_s).to eq("#{sorted[0]}, #{sorted[1]}")
    end
  end

  context '#arch_to_s' do
    subject(:arch_to_s) do
      metasploit_instance.arch_to_s
    end

    it 'calls #architecture_abbreviations_to_s' do
      expect(metasploit_instance).to receive(:architecture_abbreviations_to_s)

      arch_to_s
    end
  end

  context '#compatible_architecture_abbreviation?' do
    subject(:compatible_architecture_abbreviation?) do
      metasploit_instance.compatible_architecture_abbreviation?(architecture_abbreviation)
    end

    context 'with ARCH_ANY' do
      let(:architecture_abbreviation) do
        ARCH_ANY
      end

      it { should be_true }
    end

    context 'without ARCH_ANY' do
      #
      # lets
      #

      let(:architecture_abbreviation) do
        FactoryGirl.generate :metasploit_model_architecture_abbreviation
      end

      #
      # Callbacks
      #

      before(:each) do
        metasploit_instance.architecture_abbreviations = architecture_abbreviations
      end

      context 'in #architecture_abbreviations' do
        let(:architecture_abbreviations) do
          [architecture_abbreviation]
        end

        it { should be_true }
      end

      context 'not in #architecture_abbreviations' do
        let(:architecture_abbreviations) do
          []
        end

        it { should be_false }
      end
    end
  end

  context '#each_arch' do
    #
    # Methods
    #

    # no subject because of need to pass the block
    def each_arch(&block)
      metasploit_instance.each_arch(&:block)
    end

    #
    # lets
    #

    let(:architecture_abbreviations) do
      Metasploit::Model::Architecture::ABBREVIATIONS.sample(2)
    end

    #
    # Callbacks
    #

    before(:each) do
      metasploit_instance.architecture_abbreviations = architecture_abbreviations
    end

    it 'calls #each on #architecture_abbreviations' do
      expect(architecture_abbreviations).to receive(:each)

      each_arch {}
    end
  end
end