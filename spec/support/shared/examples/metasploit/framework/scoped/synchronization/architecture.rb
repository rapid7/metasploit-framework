shared_examples_for 'Metasploit::Framework::Scoped::Synchronization::Architecture' do |options={}|
  options.assert_valid_keys(:join_association, :join_class)

  join_association = options.fetch(:join_association)
  join_class = options.fetch(:join_class)

  it { should be_a Metasploit::Framework::Scoped::Logging }

  context 'join_association' do
    subject(:join_association) do
      described_class.join_association
    end

    it { should == join_association }
  end


  context '#added_architectures' do
    subject(:added_architectures) do
      synchronization.added_architectures
    end

    before(:each) do
      synchronization.stub(added_attributes_set: added_attributes_set)
    end

    context 'with #added_attributes_set' do
      let(:abbreviation) do
        architecture.abbreviation
      end

      let(:added_attributes_set) do
        Set.new(
            [
                abbreviation
            ]
        )
      end

      let(:architecture) do
        FactoryGirl.generate :mdm_architecture
      end

      it 'should include matching Mdm::Architecture' do
        added_architectures.should include(architecture)
      end
    end

    context 'without #added_attributes_set' do
      let(:added_attributes_set) do
        Set.new
      end

      it { should == [] }

      it 'should not query database' do
        Mdm::Architecture.should_not_receive(:where)

        added_architectures
      end
    end
  end

  context '#associated' do
    subject(:associated) do
      synchronization.associated
    end

    it "should be destination.#{join_association}" do
      associated.should == destination.send(join_association)
    end
  end


  context '#build_added' do
    subject(:build_added) do
      synchronization.build_added
    end

    #
    # lets
    #

    let(:added_architectures) do
      2.times.collect {
        FactoryGirl.generate :mdm_architecture
      }
    end

    #
    # callbacks
    #

    before(:each) do
      synchronization.stub(added_architectures: added_architectures)
    end

    it "should build an instance of #{join_class} for each added architecture" do
      build_added

      actual_architectures = destination.send(join_association).map(&:architecture)
      expect(actual_architectures).to match_array(added_architectures)
    end
  end

  context '#destroy_removed' do
    subject(:destroy_removed) do
      synchronization.destroy_removed
    end

    context 'with new record' do
      it 'should not destroy anything' do
        expect {
          destroy_removed
        }.not_to change(join_class, :count)
      end
    end

    context 'without new record' do
      #
      # lets
      #

      let(:destination) do
        persistable_destination
      end

      #
      # callbacks
      #

      before(:each) do
        destination.save!

        synchronization.stub(removed_attributes_set: removed_attributes_set)
      end

      context 'with #removed_attributes_set' do
        let(:abbreviation) do
          destination_abbreviations.sample
        end

        let(:destination_abbreviations) do
          destination.send(join_association).map(&:architecture).map(&:abbreviation)
        end

        let(:removed_attributes_set) do
          Set.new(
              [
                  abbreviation
              ]
          )
        end

        it "should remove #{join_class} with architecture with matching abbreviation" do
          expect {
            destroy_removed
          }.to change(join_class, :count)
        end
      end

      context 'without #removed_attributes_set' do
        let(:removed_attributes_set) do
          Set.new
        end

        it 'should not destroy anything' do
          expect {
            destroy_removed
          }.not_to change(join_class, :count)
        end
      end
    end
  end

  context '#scope' do
    subject(:scope) do
      synchronization.scope
    end

    context 'joins' do
      subject(:joins) do
        scope.joins_values
      end

      it { should include :architecture }
    end
  end

  context '#source_architecture_abbreviations' do
    subject(:source_architecture_abbreviations) do
      synchronization.source_architecture_abbreviations
    end

    context 'with NoMethodError' do
      #
      # lets
      #

      let(:error) do
        NoMethodError.new('message')
      end

      #
      # callbacks
      #

      before(:each) do
        synchronization.source.should_receive(:architecture_abbreviations).and_raise(error)
      end

      it 'should log scoped error' do
        synchronization.should_receive(:log_scoped_error).with(synchronization.destination, error)

        source_architecture_abbreviations
      end

      it { should == [] }
    end

    context 'without NoMethodError' do
      it 'should be source.architecture_abbreviations' do
        source_architecture_abbreviations.should == synchronization.source.architecture_abbreviations
      end
    end
  end

  context '#synchronize' do
    subject(:synchronize) do
      synchronization.synchronize
    end

    it 'should destroy removed and build added' do
      synchronization.should_receive(:destroy_removed).ordered
      synchronization.should_receive(:build_added).ordered

      synchronize
    end
  end
end