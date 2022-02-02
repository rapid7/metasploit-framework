RSpec.shared_examples_for 'Msf::DBManager::ModuleCache' do

  if ENV['REMOTE_DB']
    before {skip("Module Cache methods will not be ported, instead the newer module metadata cache should be used")}
  end

  it { is_expected.to respond_to :match_values }
  it { is_expected.to respond_to :module_to_details_hash }
  it { is_expected.to respond_to :modules_cached }
  it { is_expected.to respond_to :modules_cached= }
  it { is_expected.to respond_to :modules_caching }
  it { is_expected.to respond_to :modules_caching= }

  context '#purge_all_module_details' do
    def purge_all_module_details
      db_manager.purge_all_module_details
    end

    let(:migrated) do
      false
    end

    let(:module_detail_count) do
      2
    end

    let!(:module_details) do
      FactoryBot.create_list(
          :mdm_module_detail,
          module_detail_count
      )
    end

    before(:example) do
      allow(db_manager).to receive(:migrated).and_return(migrated)
    end

    context 'with migrated' do
      let(:migrated) do
        true
      end

      let(:modules_caching) do
        false
      end

      before(:example) do
        allow(db_manager).to receive(:modules_caching).and_return(modules_caching)
      end

      context 'with modules_caching' do
        let(:modules_caching) do
          true
        end

        it 'should not destroy Mdm::Module::Details' do
          expect {
            purge_all_module_details
          }.to_not change(Mdm::Module::Detail, :count)
        end
      end

      context 'without modules_caching' do
        it 'should destroy all Mdm::Module::Details' do
          expect {
            purge_all_module_details
          }.to change(Mdm::Module::Detail, :count).by(-module_detail_count)
        end
      end
    end

    context 'without migrated' do
      it 'should not destroy Mdm::Module::Details' do
        expect {
          purge_all_module_details
        }.to_not change(Mdm::Module::Detail, :count)
      end
    end
  end

  context '#remove_module_details' do
    def remove_module_details
      db_manager.remove_module_details(mtype, refname)
    end

    let(:migrated) do
      false
    end

    let(:mtype) do
      FactoryBot.generate :mdm_module_detail_mtype
    end

    let(:refname) do
      FactoryBot.generate :mdm_module_detail_refname
    end

    let!(:module_detail) do
      FactoryBot.create(
          :mdm_module_detail
      )
    end

    before(:example) do
      allow(db_manager).to receive(:migrated).and_return(migrated)
    end

    context 'with migrated' do
      let(:migrated) do
        true
      end

      let!(:module_detail) do
        FactoryBot.create(:mdm_module_detail)
      end

      context 'with matching Mdm::Module::Detail' do
        let(:mtype) do
          module_detail.mtype
        end

        let(:refname) do
          module_detail.refname
        end

        it 'should destroy Mdm::Module::Detail' do
          expect {
            remove_module_details
          }.to change(Mdm::Module::Detail, :count).by(-1)
        end
      end

      context 'without matching Mdm::Module::Detail' do
        it 'should not destroy Mdm::Module::Detail' do
          expect {
            remove_module_details
          }.to_not change(Mdm::Module::Detail, :count)
        end
      end
    end

    context 'without migrated' do
      it 'should not destroy Mdm::Module::Detail' do
        expect {
          remove_module_details
        }.to_not change(Mdm::Module::Detail, :count)
      end
    end
  end

  context '#search_modules' do
    subject(:search_modules) do
      db_manager.search_modules(search_string)
    end

    let(:module_details) do
      search_modules.to_a
    end

    context 'with author keyword' do
      let(:search_string) do
        # us inspect so strings with spaces are quoted correctly
        "author:#{author}"
      end

      let!(:module_authors) do
        FactoryBot.create_list(:mdm_module_author, 2)
      end

      let(:target_module_author) do
        module_authors.first
      end

      context 'with Mdm::Module::Author#email' do
        let(:author) do
          target_module_author.email
        end

        it 'should match Mdm::Module::Author#email' do
          expect(module_details.count).to be > 0

          expect(
            module_details.all? { |module_detail|
              module_detail.authors.any? { |module_author|
                module_author.email == target_module_author.email
              }
            }
          ).to eq true
        end
      end

      context 'with Mdm::Module::Author#name' do
        let(:author) do
          # use inspect to quote space in name
          target_module_author.name.inspect
        end

        it 'should match Mdm::Module::Author#name' do
          expect(module_details.count).to be > 0

          expect(
            module_details.all? { |module_detail|
              module_detail.authors.any? { |module_author|
                module_author.name == target_module_author.name
              }
            }
          ).to eq true
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
        FactoryBot.create_list(:mdm_module_detail, 2)
      end

      let(:target_module_detail) do
        existing_module_details.first
      end

      context 'with Mdm::Module::Detail#fullname' do
        let(:name) do
          target_module_detail.fullname
        end

        it 'should match Mdm::Module::Detail#fullname' do
          expect(module_details.count).to be > 0

          expect(
            module_details.all? { |module_detail|
              module_detail.fullname == target_module_detail.fullname
            }
          ).to eq true
        end
      end

      context 'with Mdm::Module::Detail#name' do
        let(:name) do
          # use inspect so spaces are inside quotes
          target_module_detail.name.inspect
        end

        it 'should match Mdm::Module::Detail#name' do
          expect(module_details.count).to be > 0

          expect(
            module_details.all? { |module_detail|
              module_detail.name == target_module_detail.name
            }
          ).to eq true
        end
      end
    end

    it_should_behave_like 'Msf::DBManager#search_modules Mdm::Module::Platform#name or Mdm::Module::Target#name keyword', :os

    it_should_behave_like 'Msf::DBManager#search_modules Mdm::Module::Platform#name or Mdm::Module::Target#name keyword', :platform

    context 'with ref keyword' do
      let(:ref) do
        FactoryBot.generate :mdm_module_ref_name
      end

      let(:search_string) do
        # use inspect to quote spaces in string
        "ref:#{ref.inspect}"
      end

      let!(:module_ref) do
        FactoryBot.create(:mdm_module_ref)
      end

      context 'with Mdm::Module::Ref#name' do
        let(:ref) do
          module_ref.name
        end

        it 'should match Mdm::Module::Ref#name' do
          expect(module_details.count).to be > 0

          expect(
            module_details.all? { |module_detail|
              module_detail.refs.any? { |module_ref|
                module_ref.name == ref
              }
            }
          ).to eq true
        end
      end

      context 'without Mdm::Module::Ref#name' do
        it 'should not match Mdm::Module::Ref#name' do
          expect(module_details.count).to eq 0
        end
      end
    end

    context 'with type keyword' do
      let(:type) do
        FactoryBot.generate :mdm_module_detail_mtype
      end

      let(:search_string) do
        "type:#{type}"
      end

      let(:target_module_detail) do
        all_module_details.first
      end

      let!(:all_module_details) do
        FactoryBot.create_list(:mdm_module_detail, 2)
      end

      context 'with Mdm::Module::Ref#name' do
        let(:type) do
          target_module_detail.mtype
        end

        it 'should match Mdm::Module::Detail#mtype' do
          expect(module_details.count).to be > 0

          expect(
            module_details.all? { |module_detail|
              module_detail.mtype == type
            }
          ).to eq true
        end
      end

      context 'without Mdm::Module::Detail#mtype' do
        it 'should not match Mdm::Module::Detail#mtype' do
          expect(module_details.count).to eq 0
        end
      end
    end

    context 'without keyword' do
      context 'with Mdm::Module::Action#name' do
        let(:search_string) do
          module_action.name
        end

        let!(:module_action) do
          FactoryBot.create(:mdm_module_action)
        end

        it 'should match Mdm::Module::Action#name' do
          expect(module_details.count).to be > 0

          expect(
            module_details.all? { |module_detail|
              module_detail.actions.any? { |module_action|
                module_action.name == search_string
              }
            }
          ).to eq true
        end
      end

      context 'with Mdm::Module::Arch#name' do
        let(:search_string) do
          module_arch.name
        end

        let!(:module_arch) do
          FactoryBot.create(:mdm_module_arch)
        end

        it 'should match Mdm::Module::Arch#name' do
          expect(module_details.count).to be > 0

          expect(
            module_details.all? { |module_detail|
              module_detail.archs.any? { |module_arch|
                module_arch.name == search_string
              }
            }
          ).to eq true
        end
      end

      context 'with Mdm::Module::Author#name' do
        let(:search_string) do
          module_author.name
        end

        let!(:module_author) do
          FactoryBot.create(:mdm_module_author)
        end

        it 'should match Mdm::Module::Author#name' do
          expect(module_details.count).to be > 0

          expect(
            module_details.all? { |module_detail|
              module_detail.authors.any? { |module_author|
                module_author.name == search_string
              }
            }
          ).to eq true
        end
      end

      context 'with Mdm::Module::Detail' do
        let(:target_module_detail) do
          all_module_details.first
        end

        let!(:all_module_details) do
          FactoryBot.create_list(:mdm_module_detail, 3)
        end

        context 'with #description' do
          let(:search_string) do
            # use inspect to quote spaces in string
            target_module_detail.description.inspect
          end

          it 'should match Mdm::Module::Detail#description' do
            expect(module_details.count).to eq 1

            expect(
              module_details.all? { |module_detail|
                module_detail.description == target_module_detail.description
              }
            ).to eq true
          end
        end

        context 'with #fullname' do
          let(:search_string) do
            target_module_detail.fullname
          end

          it 'should match Mdm::Module::Detail#fullname' do
            expect(module_details.count).to eq 1

            expect(
              module_details.all? { |module_detail|
                module_detail.fullname == search_string
              }
            ).to eq true
          end
        end

        context 'with #name' do
          let(:search_string) do
            # use inspect to quote spaces in string
            target_module_detail.name.inspect
          end

          it 'should match Mdm::Module::Detail#name' do
            expect(module_details.count).to eq 1

            expect(
              module_details.all? { |module_detail|
                module_detail.name == target_module_detail.name
              }
            ).to eq true
          end
        end
      end

      context 'with Mdm::Module::Platform#name' do
        let(:search_string) do
          module_platform.name
        end

        let!(:module_platform) do
          FactoryBot.create(:mdm_module_platform)
        end

        it 'should match Mdm::Module::Platform#name' do
          expect(module_details.count).to be > 0

          expect(
            module_details.all? { |module_detail|
              module_detail.platforms.any? { |module_platform|
                module_platform.name == search_string
              }
            }
          ).to eq true
        end
      end

      context 'with Mdm::Module::Ref#name' do
        let(:search_string) do
          module_ref.name
        end

        let!(:module_ref) do
          FactoryBot.create(:mdm_module_ref)
        end

        it 'should match Mdm::Module::Ref#name' do
          expect(module_details.count).to be > 0

          expect(
            module_details.all? { |module_detail|
              module_detail.refs.any? { |module_ref|
                module_ref.name == search_string
              }
            }
          ).to eq true
        end
      end

      context 'with Mdm::Module::Target#name' do
        let(:search_string) do
          module_target.name
        end

        let!(:module_target) do
          FactoryBot.create(:mdm_module_target)
        end

        it 'should match Mdm::Module::Target#name' do
          expect(module_details.count).to be > 0

          expect(
            module_details.all? { |module_detail|
              module_detail.targets.any? { |module_target|
                module_target.name == search_string
              }
            }
          ).to eq true
        end
      end
    end
  end

  context '#update_all_module_details' do
    def update_all_module_details
      db_manager.update_all_module_details
    end

    let(:migrated) do
      false
    end

    before(:example) do
      allow(db_manager).to receive(:migrated).and_return(migrated)
    end

    context 'with migrated' do
      let(:migrated) do
        true
      end

      let(:modules_caching) do
        true
      end

      before(:example) do
        allow(db_manager).to receive(:modules_caching).and_return(modules_caching)
      end

      context 'with modules_caching' do
        it 'should not update module details' do
          expect(db_manager).not_to receive(:update_module_details)

          update_all_module_details
        end
      end

      context 'without modules_caching' do
        let(:modules_caching) do
          false
        end

        it 'should set framework.cache_thread to current thread and then nil' do
          expect(framework).to receive(:cache_thread=).with(Thread.current).ordered
          expect(framework).to receive(:cache_thread=).with(nil).ordered

          update_all_module_details
        end

        it 'should set modules_cached to false and then true' do
          expect(db_manager).to receive(:modules_cached=).with(false).ordered
          expect(db_manager).to receive(:modules_cached=).with(true).ordered

          update_all_module_details
        end

        it 'should set modules_caching to true and then false' do
          expect(db_manager).to receive(:modules_caching=).with(true).ordered
          expect(db_manager).to receive(:modules_caching=).with(false).ordered

          update_all_module_details
        end

        context 'with Mdm::Module::Details' do
          let(:module_pathname) do
            parent_pathname.join(
                'exploits',
                "#{reference_name}.rb"
            )
          end

          let(:modification_time) do
            module_pathname.mtime
          end

          let(:parent_pathname) do
            Metasploit::Framework.root.join('modules')
          end

          let(:reference_name) do
            'windows/smb/ms08_067_netapi'
          end

          let(:type) do
            'exploit'
          end

          let!(:module_detail) do
            # needs to reference a real module so that it can be loaded
            FactoryBot.create(
                :mdm_module_detail,
                :file => module_pathname.to_path,
                :mtime => modification_time,
                :mtype => type,
                :ready => ready,
                :refname => reference_name
            )
          end

          context '#ready' do
            context 'false' do
              let(:ready) do
                false
              end

              it_should_behave_like 'Msf::DBManager#update_all_module_details refresh'
            end

            context 'true' do
              let(:ready) do
                true
              end

              context 'with existing Mdm::Module::Detail#file' do
                context 'with same Mdm::Module::Detail#mtime and File.mtime' do
                  it 'should not update module details' do
                    expect(db_manager).not_to receive(:update_module_details)

                    update_all_module_details
                  end
                end

                context 'without same Mdm::Module::Detail#mtime and File.mtime' do
                  let(:modification_time) do
                    # +1 as rand can return 0 and the time must be different for
                    # this context.
                    1.days.ago
                  end

                  it_should_behave_like 'Msf::DBManager#update_all_module_details refresh'
                end
              end

              # Emulates a module being removed or renamed
              context 'without existing Mdm::Module::Detail#file' do
                # have to compute modification manually since the
                # `module_pathname` refers to a non-existent file and
                # `module_pathname.mtime` would error.
                let(:modification_time) do
                  Time.now.utc - 1.day
                end

                let(:module_pathname) do
                  parent_pathname.join('exploits', 'deleted.rb')
                end

                it 'should not update module details' do
                  expect(db_manager).not_to receive(:update_module_details)

                  update_all_module_details
                end
              end
            end
          end
        end
      end
    end

    context 'without migrated' do
      it 'should not update module details' do
        expect(db_manager).not_to receive(:update_module_details)

        update_all_module_details
      end
    end
  end

  context '#update_module_details' do
    include_context 'Metasploit::Framework::Spec::Constants cleaner'

    def update_module_details
      db_manager.update_module_details(module_instance)
    end

    let(:loader) do
      loader = framework.modules.send(:loaders).find { |loader|
        loader.loadable?(parent_path)
      }

      # Override load_error so that rspec will print it instead of going to framework log
      def loader.load_error(module_path, error)
        raise error
      end

      loader
    end

    let(:migrated) do
      false
    end

    let(:module_instance) do
      # make sure the module is loaded into the module_set
      loaded = loader.load_module(parent_path, module_type, module_reference_name)

      unless loaded
        module_path = loader.module_path(parent_path, type, module_reference_name)

        fail "#{description} failed to load: #{module_path}"
      end

      module_set.create(module_reference_name)
    end

    let(:module_set) do
      framework.modules.module_set(module_type)
    end

    let(:module_type) do
      'exploit'
    end

    let(:module_reference_name) do
      'windows/smb/ms08_067_netapi'
    end

    let(:parent_path) do
      parent_pathname.to_path
    end

    let(:parent_pathname) do
      Metasploit::Framework.root.join('modules')
    end

    let(:type_directory) do
      'exploits'
    end

    before(:example) do
      allow(db_manager).to receive(:migrated).and_return(migrated)
    end

    context 'with migrated' do
      let(:migrated) do
        true
      end

      it 'should call module_to_details_hash to get Mdm::Module::Detail attributes and association attributes' do
        expect(db_manager).to receive(:module_to_details_hash).and_call_original

        update_module_details
      end

      it 'should create an Mdm::Module::Detail' do
        expect {
          update_module_details
        }.to change(Mdm::Module::Detail, :count).by(1)
      end


      context 'module_to_details_hash' do
        let(:module_to_details_hash) do
          {
              :mtype => module_type,
              :privileged => privileged,
              :rank => rank,
              :refname => module_reference_name,
              :stance => stance
          }
        end

        let(:privileged) do
          FactoryBot.generate :mdm_module_detail_privileged
        end

        let(:rank) do
          FactoryBot.generate :mdm_module_detail_rank
        end

        let(:stance) do
          FactoryBot.generate :mdm_module_detail_stance
        end

        before(:example) do
          allow(db_manager).to receive(
              :module_to_details_hash
          ).with(
              module_instance
          ).and_return(
              module_to_details_hash
          )
        end

        context 'Mdm::Module::Detail' do
          subject(:module_detail) do
            Mdm::Module::Detail.last
          end

          before(:example) do
            update_module_details
          end

          it { expect(subject.mtype).to eq(module_type) }
          it { expect(subject.privileged).to eq(privileged) }
          it { expect(subject.rank).to eq(rank) }
          it { expect(subject.ready).to be_truthy }
          it { expect(subject.refname).to eq(module_reference_name) }
          it { expect(subject.stance).to eq(stance) }
        end

        context 'with :bits' do
          let(:bits) do
            []
          end

          before(:example) do
            module_to_details_hash[:bits] = bits
          end

          context 'with :action' do
            let(:name) do
              FactoryBot.generate :mdm_module_action_name
            end

            let(:bits) do
              super() << [
                  :action,
                  {
                      :name => name
                  }
              ]
            end

            it 'should create an Mdm::Module::Action' do
              expect {
                update_module_details
              }.to change(Mdm::Module::Action, :count).by(1)
            end

            context 'Mdm::Module::Action' do
              subject(:module_action) do
                module_detail.actions.last
              end

              let(:module_detail) do
                Mdm::Module::Detail.last
              end

              before(:example) do
                update_module_details
              end

              it { expect(subject.name).to eq(name) }
            end
          end

          context 'with :arch' do
            let(:name) do
              FactoryBot.generate :mdm_module_arch_name
            end

            let(:bits) do
              super() << [
                  :arch,
                  {
                      :name => name
                  }
              ]
            end

            it 'should create an Mdm::Module::Arch' do
              expect {
                update_module_details
              }.to change(Mdm::Module::Arch, :count).by(1)
            end

            context 'Mdm::Module::Arch' do
              subject(:module_arch) do
                module_detail.archs.last
              end

              let(:module_detail) do
                Mdm::Module::Detail.last
              end

              before(:example) do
                update_module_details
              end

              it { expect(subject.name).to eq(name) }
            end
          end

          context 'with :author' do
            let(:email) do
              FactoryBot.generate :mdm_module_author_email
            end

            let(:name) do
              FactoryBot.generate :mdm_module_author_name
            end

            let(:bits) do
              super() << [
                  :author,
                  {
                      :email => email,
                      :name => name
                  }
              ]
            end

            it 'should create an Mdm::Module::Author' do
              expect {
                update_module_details
              }.to change(Mdm::Module::Author, :count).by(1)
            end

            context 'Mdm::Module::Author' do
              subject(:module_author) do
                module_detail.authors.last
              end

              let(:module_detail) do
                Mdm::Module::Detail.last
              end

              before(:example) do
                update_module_details
              end

              it { expect(subject.name).to eq(name) }
              it { expect(subject.email).to eq(email) }
            end
          end

          context 'with :platform' do
            let(:bits) do
              super() << [
                  :platform,
                  {
                      :name => name
                  }
              ]
            end

            let(:name) do
              FactoryBot.generate :mdm_module_platform_name
            end

            it 'should create an Mdm::Module::Platform' do
              expect {
                update_module_details
              }.to change(Mdm::Module::Platform, :count).by(1)
            end

            context 'Mdm::Module::Platform' do
              subject(:module_platform) do
                module_detail.platforms.last
              end

              let(:module_detail) do
                Mdm::Module::Detail.last
              end

              before(:example) do
                update_module_details
              end

              it { expect(subject.name).to eq(name) }
            end
          end

          context 'with :ref' do
            let(:bits) do
              super() << [
                  :ref,
                  {
                      :name => name
                  }
              ]
            end

            let(:name) do
              FactoryBot.generate :mdm_module_ref_name
            end

            it 'should create an Mdm::Module::Ref' do
              expect {
                update_module_details
              }.to change(Mdm::Module::Ref, :count).by(1)
            end

            context 'Mdm::Module::Ref' do
              subject(:module_ref) do
                module_detail.refs.last
              end

              let(:module_detail) do
                Mdm::Module::Detail.last
              end

              before(:example) do
                update_module_details
              end

              it { expect(subject.name).to eq(name) }
            end
          end

          context 'with :target' do
            let(:bits) do
              super() << [
                  :target,
                  {
                      :index => index,
                      :name => name
                  }
              ]
            end

            let(:index) do
              FactoryBot.generate :mdm_module_target_index
            end

            let(:name) do
              FactoryBot.generate :mdm_module_target_name
            end

            it 'should create an Mdm::Module::Target' do
              expect {
                update_module_details
              }.to change(Mdm::Module::Target, :count).by(1)
            end

            context 'Mdm::Module::Target' do
              subject(:module_target) do
                module_detail.targets.last
              end

              let(:module_detail) do
                Mdm::Module::Detail.last
              end

              before(:example) do
                update_module_details
              end

              it { expect(subject.index).to eq(index) }
              it { expect(subject.name).to eq(name) }
            end
          end
        end
      end

      it_should_behave_like 'Msf::DBManager#update_module_details with module',
                            :reference_name => 'admin/2wire/xslt_password_reset',
                            :type => 'auxiliary'

      it_should_behave_like 'Msf::DBManager#update_module_details with module',
                            :reference_name => 'generic/none',
                            :type => 'encoder'

      it_should_behave_like 'Msf::DBManager#update_module_details with module',
                            :reference_name => 'windows/smb/ms08_067_netapi',
                            :type => 'exploit'

      it_should_behave_like 'Msf::DBManager#update_module_details with module',
                            :reference_name => 'x64/simple',
                            :type => 'nop'

      # @todo determine how to load a single payload to test payload type outside of msfconsole

      it_should_behave_like 'Msf::DBManager#update_module_details with module',
                            :reference_name => 'windows/escalate/screen_unlock',
                            :type => 'post'
    end

    context 'without migrated' do
      it 'should not create an Mdm::Module::Detail' do
        expect {
          update_module_details
        }.to_not change(Mdm::Module::Detail, :count)
      end
    end
  end
end
