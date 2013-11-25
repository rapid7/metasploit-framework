shared_examples_for 'Metasploit::Framework::Scoped::Synchronization::Platform' do |options={}|
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


  context '#added_platforms' do
    subject(:added_platforms) do
      synchronization.added_platforms
    end

    before(:each) do
      synchronization.stub(added_attributes_set: added_attributes_set)
    end

    context 'with #added_attributes_set' do
      let(:fully_qualified_name) do
        platform.fully_qualified_name
      end

      let(:added_attributes_set) do
        Set.new(
            [
                fully_qualified_name
            ]
        )
      end

      let(:platform) do
        FactoryGirl.generate :mdm_platform
      end

      it 'should include matching Mdm::Platform' do
        added_platforms.should include(platform)
      end
    end

    context 'without #added_attributes_set' do
      let(:added_attributes_set) do
        Set.new
      end

      it { should == [] }

      it 'should not query database' do
        Mdm::Platform.should_not_receive(:where)

        added_platforms
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

    let(:added_platforms) do
      2.times.collect {
        FactoryGirl.generate :mdm_platform
      }
    end

    #
    # callbacks
    #

    before(:each) do
      synchronization.stub(added_platforms: added_platforms)
    end

    it "should build an instance of #{join_class} for each added platform" do
      build_added

      actual_platforms = destination.send(join_association).map(&:platform)
      expect(actual_platforms).to match_array(added_platforms)
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
        let(:fully_qualified_name) do
          destination_fully_qualified_names.sample
        end

        let(:destination_fully_qualified_names) do
          destination.send(join_association).map(&:platform).map(&:fully_qualified_name)
        end

        let(:removed_attributes_set) do
          Set.new(
              [
                  fully_qualified_name
              ]
          )
        end

        it "should remove #{join_class} with platform with matching fully_qualified_name" do
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

      it { should include :platform }
    end
  end

  context '#source_platform_list' do
    subject(:source_platform_list) do
      synchronization.source_platform_list
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
        synchronization.source.should_receive(:platform_list).and_raise(error)
      end

      it 'should log scoped error' do
        synchronization.should_receive(:log_scoped_error).with(synchronization.destination, error)

        source_platform_list
      end

      it { should be_a Msf::Module::PlatformList }
      it { should be_empty }
    end

    context 'without NoMethodError' do
      it 'should be source.platform_list' do
        source_platform_list.should == synchronization.source.platform_list
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