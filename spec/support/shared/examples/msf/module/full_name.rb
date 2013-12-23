shared_examples_for 'Msf::Module::FullName' do
  #
  # Shared Examples
  #

  shared_examples_for 'delegates to self.class' do |method|
    context method do
      subject(method) do
        metasploit_instance.send(method)
      end

      it 'delegates to self.class' do
        expected = double(method)
        described_class.stub(method => expected)

        send(method).should == expected
      end
    end
  end

  context '#fullname' do
    subject(:fullname) do
      described_class.fullname
    end

    it 'should call #full_name' do
      described_class.should_receive(:full_name)

      fullname
    end
  end

  context 'full_name' do
    subject(:full_name) do
      subclass.full_name
    end

    let(:subclass) do
      Class.new(described_class)
    end

    it 'is memoized' do
      expected = double('full_name')
      subclass.instance_variable_set :@full_name, expected

      full_name.should == expected
    end

    context 'without memoized value' do
      include_context 'database cleaner'

      #
      # lets
      #

      let(:module_class) do
        FactoryGirl.build(
            :mdm_module_class
        )
      end

      #
      # Callbacks
      #

      before(:each) do
        subclass.stub(module_class: module_class)
      end

      it 'should use module_class.full_name' do
        full_name.should == module_class.full_name
      end
    end
  end

  context 'refname' do
    subject(:refname) do
      described_class.refname
    end

    it 'calls #reference_name' do
      described_class.should_receive(:reference_name)

      refname
    end
  end

  context 'reference_name' do
    subject(:reference_name) do
      subclass.reference_name
    end

    let(:subclass) do
      Class.new(described_class)
    end

    it 'is memoized' do
      expected = double('reference_name')
      subclass.instance_variable_set :@reference_name, expected

      reference_name.should == expected
    end

    context 'without memoized value' do
      include_context 'database cleaner'

      #
      # lets
      #

      let(:module_class) do
        FactoryGirl.build(
            :mdm_module_class
        )
      end

      #
      # Callbacks
      #

      before(:each) do
        subclass.stub(module_class: module_class)
      end

      it 'should use module_class.reference_name' do
        reference_name.should == module_class.reference_name
      end
    end
  end

  context 'shortname' do
    subject(:shortname) do
      described_class.shortname
    end

    it 'calls #short_name' do
      described_class.should_receive(:short_name)

      shortname
    end
  end

  context 'short_name' do
    subject(:short_name) do
      described_class.short_name
    end

    #
    # lets
    #

    let(:expected_short_name) do
      'expected_short_name'
    end

    let(:reference_name) do
      "parts/that/are/stripped/for/#{expected_short_name}"
    end

    #
    # Callbacks
    #

    before(:each) do
      described_class.stub(reference_name: reference_name)
    end

    it 'should be last name in reference_name' do
      short_name.should == expected_short_name
    end
  end

  it_should_behave_like 'delegates to self.class', :full_name
  it_should_behave_like 'delegates to self.class', :reference_name
  it_should_behave_like 'delegates to self.class', :short_name

  context '#fullname' do
    subject(:fullname) do
      metasploit_instance.fullname
    end

    it 'calls #full_name' do
      metasploit_instance.should_receive(:full_name)

      fullname
    end
  end

  context '#refname' do
    subject(:refname) do
      metasploit_instance.refname
    end

    it 'calls #reference_name' do
      metasploit_instance.should_receive(:reference_name)

      refname
    end
  end

  context '#shortname' do
    subject(:shortname) do
      metasploit_instance.shortname
    end

    it 'calls #short_name' do
      metasploit_instance.should_receive(:short_name)

      shortname
    end
  end
end