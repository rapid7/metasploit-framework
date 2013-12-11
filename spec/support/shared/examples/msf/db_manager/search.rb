shared_examples_for 'Msf::DBManager::Search' do
  context '#search_modules', :pending => 'https://www.pivotaltracker.com/story/show/56005824' do
    include_context 'database cleaner'

    subject(:search_modules) do
      db_manager.search_modules(search_string)
    end

    let(:module_details) do
      search_modules.to_a
    end

    context 'with app keyword' do
      let(:search_string) do
        "app:#{app}"
      end

      before(:each) do
        Mdm::Module::Detail::STANCES.each do |stance|
          FactoryGirl.create(:mdm_module_detail, :stance => stance)
        end
      end

      context 'with client' do
        let(:app) do
          'client'
        end

        it "should match Mdm::Module::Detail#stance 'passive'" do
          module_details.count.should > 0

          module_details.all? { |module_detail|
            module_detail.stance == 'passive'
          }.should be_true
        end
      end

      context 'with server' do
        let(:app) do
          'server'
        end

        it "should match Mdm::Module::Detail#stance 'aggressive'" do
          module_details.count.should > 0

          module_details.all? { |module_detail|
            module_detail.stance == 'aggressive'
          }.should be_true
        end
      end
    end

    context 'with author keyword' do
      let(:search_string) do
        # us inspect so strings with spaces are quoted correctly
        "author:#{author}"
      end

      let!(:module_authors) do
        FactoryGirl.create_list(:mdm_module_author, 2)
      end

      let(:target_module_author) do
        module_authors.first
      end

      context 'with Mdm::Module::Author#email' do
        let(:author) do
          target_module_author.email
        end

        it 'should match Mdm::Module::Author#email' do
          module_details.count.should > 0

          module_details.all? { |module_detail|
            module_detail.authors.any? { |module_author|
              module_author.email == target_module_author.email
            }
          }.should be_true
        end
      end

      context 'with Mdm::Module::Author#name' do
        let(:author) do
          # use inspect to quote space in name
          target_module_author.name.inspect
        end

        it 'should match Mdm::Module::Author#name' do
          module_details.count.should > 0

          module_details.all? { |module_detail|
            module_detail.authors.any? { |module_author|
              module_author.name == target_module_author.name
            }
          }.should be_true
        end
      end
    end

    it_should_behave_like 'Msf::DBManager#search_modules Mdm::Module::Ref#name keyword', :bid
    it_should_behave_like 'Msf::DBManager#search_modules Mdm::Module::Ref#name keyword', :cve
    it_should_behave_like 'Msf::DBManager#search_modules Mdm::Module::Ref#name keyword', :edb

    context 'with name keyword' do
      let(:search_string) do
        "name:#{name}"
      end

      let!(:existing_module_details) do
        FactoryGirl.create_list(:mdm_module_detail, 2)
      end

      let(:target_module_detail) do
        existing_module_details.first
      end

      context 'with Mdm::Module::Detail#fullname' do
        let(:name) do
          target_module_detail.fullname
        end

        it 'should match Mdm::Module::Detail#fullname' do
          module_details.count.should > 0

          module_details.all? { |module_detail|
            module_detail.fullname == target_module_detail.fullname
          }.should be_true
        end
      end

      context 'with Mdm::Module::Detail#name' do
        let(:name) do
          # use inspect so spaces are inside quotes
          target_module_detail.name.inspect
        end

        it 'should match Mdm::Module::Detail#name' do
          module_details.count.should > 0

          module_details.all? { |module_detail|
            module_detail.name == target_module_detail.name
          }.should be_true
        end
      end
    end

    it_should_behave_like 'Msf::DBManager#search_modules Mdm::Module::Platform#name or Mdm::Module::Target#name keyword', :os

    it_should_behave_like 'Msf::DBManager#search_modules Mdm::Module::Ref#name keyword', :osvdb

    it_should_behave_like 'Msf::DBManager#search_modules Mdm::Module::Platform#name or Mdm::Module::Target#name keyword', :platform

    context 'with ref keyword' do
      let(:ref) do
        FactoryGirl.generate :mdm_module_ref_name
      end

      let(:search_string) do
        # use inspect to quote spaces in string
        "ref:#{ref.inspect}"
      end

      let!(:module_ref) do
        FactoryGirl.create(:mdm_module_ref)
      end

      context 'with Mdm::Module::Ref#name' do
        let(:ref) do
          module_ref.name
        end

        it 'should match Mdm::Module::Ref#name' do
          module_details.count.should > 0

          module_details.all? { |module_detail|
            module_detail.refs.any? { |module_ref|
              module_ref.name == ref
            }
          }.should be_true
        end
      end

      context 'without Mdm::Module::Ref#name' do
        it 'should not match Mdm::Module::Ref#name' do
          module_details.count.should == 0
        end
      end
    end

    context 'with type keyword' do
      let(:type) do
        FactoryGirl.generate :mdm_module_detail_mtype
      end

      let(:search_string) do
        "type:#{type}"
      end

      let(:target_module_detail) do
        all_module_details.first
      end

      let!(:all_module_details) do
        FactoryGirl.create_list(:mdm_module_detail, 2)
      end

      context 'with Mdm::Module::Ref#name' do
        let(:type) do
          target_module_detail.mtype
        end

        it 'should match Mdm::Module::Detail#mtype' do
          module_details.count.should > 0

          module_details.all? { |module_detail|
            module_detail.mtype == type
          }.should be_true
        end
      end

      context 'without Mdm::Module::Detail#mtype' do
        it 'should not match Mdm::Module::Detail#mtype' do
          module_details.count.should == 0
        end
      end
    end

    context 'without keyword' do
      context 'with Mdm::Module::Action#name' do
        let(:search_string) do
          module_action.name
        end

        let!(:module_action) do
          FactoryGirl.create(:mdm_module_action)
        end

        it 'should match Mdm::Module::Action#name' do
          module_details.count.should > 0

          module_details.all? { |module_detail|
            module_detail.actions.any? { |module_action|
              module_action.name == search_string
            }
          }.should be_true
        end
      end

      context 'with Mdm::Module::Arch#name' do
        let(:search_string) do
          module_arch.name
        end

        let!(:module_arch) do
          FactoryGirl.create(:mdm_module_arch)
        end

        it 'should match Mdm::Module::Arch#name' do
          module_details.count.should > 0

          module_details.all? { |module_detail|
            module_detail.archs.any? { |module_arch|
              module_arch.name == search_string
            }
          }.should be_true
        end
      end

      context 'with Mdm::Module::Author#name' do
        let(:search_string) do
          module_author.name
        end

        let!(:module_author) do
          FactoryGirl.create(:mdm_module_author)
        end

        it 'should match Mdm::Module::Author#name' do
          module_details.count.should > 0

          module_details.all? { |module_detail|
            module_detail.authors.any? { |module_author|
              module_author.name == search_string
            }
          }.should be_true
        end
      end

      context 'with Mdm::Module::Detail' do
        let(:target_module_detail) do
          all_module_details.first
        end

        let!(:all_module_details) do
          FactoryGirl.create_list(:mdm_module_detail, 3)
        end

        context 'with #description' do
          let(:search_string) do
            # use inspect to quote spaces in string
            target_module_detail.description.inspect
          end

          it 'should match Mdm::Module::Detail#description' do
            module_details.count.should == 1

            module_details.all? { |module_detail|
              module_detail.description == target_module_detail.description
            }.should be_true
          end
        end

        context 'with #fullname' do
          let(:search_string) do
            target_module_detail.fullname
          end

          it 'should match Mdm::Module::Detail#fullname' do
            module_details.count.should == 1

            module_details.all? { |module_detail|
              module_detail.fullname == search_string
            }.should be_true
          end
        end

        context 'with #name' do
          let(:search_string) do
            # use inspect to quote spaces in string
            target_module_detail.name.inspect
          end

          it 'should match Mdm::Module::Detail#name' do
            module_details.count.should == 1

            module_details.all? { |module_detail|
              module_detail.name == target_module_detail.name
            }.should be_true
          end
        end
      end

      context 'with Mdm::Module::Platform#name' do
        let(:search_string) do
          module_platform.name
        end

        let!(:module_platform) do
          FactoryGirl.create(:mdm_module_platform)
        end

        it 'should match Mdm::Module::Platform#name' do
          module_details.count.should > 0

          module_details.all? { |module_detail|
            module_detail.platforms.any? { |module_platform|
              module_platform.name == search_string
            }
          }.should be_true
        end
      end

      context 'with Mdm::Module::Ref#name' do
        let(:search_string) do
          module_ref.name
        end

        let!(:module_ref) do
          FactoryGirl.create(:mdm_module_ref)
        end

        it 'should match Mdm::Module::Ref#name' do
          module_details.count.should > 0

          module_details.all? { |module_detail|
            module_detail.refs.any? { |module_ref|
              module_ref.name == search_string
            }
          }.should be_true
        end
      end

      context 'with Mdm::Module::Target#name' do
        let(:search_string) do
          module_target.name
        end

        let!(:module_target) do
          FactoryGirl.create(:mdm_module_target)
        end

        it 'should match Mdm::Module::Target#name' do
          module_details.count.should > 0

          module_details.all? { |module_detail|
            module_detail.targets.any? { |module_target|
              module_target.name == search_string
            }
          }.should be_true
        end
      end
    end
  end
end