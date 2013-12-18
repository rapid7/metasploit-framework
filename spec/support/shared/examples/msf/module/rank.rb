shared_examples_for 'Msf::Module::Rank' do
  #
  # Shared Examples
  #

  shared_examples_for 'delegates to self.class' do |method|
    subject(method) do
      metasploit_instance.send(method)
    end

    it "delegates #{method} to self.class" do
      expected = double(method)
      described_class.stub(method => expected)

      send(method).should == expected
    end
  end

  context 'rank_name' do
    subject(:rank_name) do
      described_class.rank_name
    end

    context 'rank_number' do
      before(:each) do
        described_class.stub(rank_number: rank_number)
      end

      context 'with 0' do
        let(:rank_number) do
          0
        end

        it { should == 'Manual' }
      end

      context 'with 100' do
        let(:rank_number) do
          100
        end

        it { should == 'Low' }
      end

      context 'with 200' do
        let(:rank_number) do
          200
        end

        it { should == 'Average' }
      end

      context 'with 300' do
        let(:rank_number) do
          300
        end

        it { should == 'Normal' }
      end

      context 'with 400' do
        let(:rank_number) do
          400
        end

        it { should == 'Good' }
      end

      context 'with 500' do
        let(:rank_number) do
          500
        end

        it { should == 'Great' }
      end

      context 'with 600' do
        let(:rank_number) do
          600
        end

        it { should == 'Excellent' }
      end

      context 'with non-rank number' do
        let(:rank_number) do
          11
        end

        it { should be_nil }
      end
    end
  end

  context 'rank_number' do
    subject(:rank_number) do
      subclass.rank_number
    end

    #
    # lets
    #

    let(:subclass) do
      Class.new(Msf::Module)
    end

    #
    # Callbacks
    #

    before(:each) do
      stub_const('MsfModuleSubclass', subclass)
    end

    context 'with Rank' do
      #
      # lets
      #

      let(:expected_rank_number) do
        42
      end

      #
      # Callbacks
      #

      before(:each) do
        stub_const("#{subclass}::Rank", expected_rank_number)
      end

      it 'equals Rank' do
        rank_number.should == expected_rank_number
      end
    end

    context 'without Rank' do
      it { should == Metasploit::Model::Module::Rank::NUMBER_BY_NAME['Normal'] }
    end
  end

  it_should_behave_like 'delegates to self.class', :rank_name
  it_should_behave_like 'delegates to self.class', :rank_number
end