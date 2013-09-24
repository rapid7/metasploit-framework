#
# Specs
#

require 'spec_helper'

#
# Project
#

require 'metasploit/framework/database'
require 'msf/core'

describe Msf::DBManager do
  include_context 'Msf::DBManager'

  subject do
    db_manager
  end

  it_should_behave_like 'Msf::DBManager::Import::MetasploitFramework::XML'
  it_should_behave_like 'Msf::DBManager::Migration'

  context '#initialize_metasploit_data_models' do
    def initialize_metasploit_data_models
      db_manager.initialize_metasploit_data_models
    end

    it 'should not add duplicate paths to ActiveRecord::Migrator.migrations_paths' do
      initialize_metasploit_data_models

      expect {
        initialize_metasploit_data_models
      }.to_not change {
        ActiveRecord::Migrator.migrations_paths.length
      }

      ActiveRecord::Migrator.migrations_paths.uniq.should == ActiveRecord::Migrator.migrations_paths
    end
  end

  context '#report_session' do
    let(:options) do
      {}
    end

    subject(:report_session) do
      db_manager.report_session(options)
    end

    context 'with active' do
      let(:active) do
        true
      end

      it 'should create connection' do
        # 1st time from with_established_connection
        # 2nd time from report_session
        ActiveRecord::Base.connection_pool.should_receive(:with_connection).exactly(2).times

        report_session
      end

      context 'with :session' do
        before(:each) do
          options[:session] = session
        end

        context 'with Msf::Session' do
          let(:exploit_datastore) do
            Msf::ModuleDataStore.new(module_instance).tap do |datastore|
              datastore['ParentModule'] = parent_module_fullname

              remote_port = rand(2 ** 16 - 1)
              datastore['RPORT'] = remote_port
            end
          end

          let(:host) do
            FactoryGirl.create(:mdm_host, :workspace => session_workspace)
          end

          let(:module_instance) do
            name = 'multi/handler'

            mock(
                'Msf::Module',
                :fullname => "exploit/#{name}",
                :framework => framework,
                :name => name
            )
          end

          let(:options_workspace) do
            FactoryGirl.create(:mdm_workspace)
          end

          let(:parent_module_fullname) do
            "exploit/#{parent_module_name}"
          end

          let(:parent_module_name) do
            'windows/smb/ms08_067_netapi'
          end

          let(:parent_path) do
            Metasploit::Framework.root.join('modules').to_path
          end

          let(:session) do
            session_class.new.tap do |session|
              session.exploit_datastore = exploit_datastore
              session.info = 'Info'
              session.platform = 'Platform'
              session.session_host = host.address
              session.sid = rand(100)
              session.type = 'Session Type'
              session.via_exploit = 'exploit/multi/handler'
              session.via_payload = 'payload/single/windows/metsvc_bind_tcp'
              session.workspace = session_workspace.name
            end
          end

          let(:session_class) do
            Class.new do
              include Msf::Session

              attr_accessor :datastore
              attr_accessor :platform
              attr_accessor :type
              attr_accessor :via_exploit
              attr_accessor :via_payload
            end
          end

          let(:session_workspace) do
            FactoryGirl.create(:mdm_workspace)
          end

          before(:each) do
            reference_name = 'multi/handler'
            path = File.join(parent_path, 'exploits', reference_name)

            FactoryGirl.create(
                :mdm_module_detail,
                :fullname => parent_module_fullname,
                :name => parent_module_name
            )
          end

          context 'with :workspace' do
            before(:each) do
              options[:workspace] = options_workspace
            end

            it 'should not find workspace from session' do
              db_manager.should_not_receive(:find_workspace)

              report_session
            end
          end

          context 'without :workspace' do
            it 'should find workspace from session' do
              db_manager.should_receive(:find_workspace).with(session.workspace).and_call_original

              report_session
            end

            it 'should pass session.workspace to #find_or_create_host' do
              db_manager.should_receive(:find_or_create_host).with(
                  hash_including(
                      :workspace => session_workspace
                  )
              ).and_return(host)

              report_session
            end
          end

          context 'with workspace from either :workspace or session' do
            it 'should pass normalized host from session as :host to #find_or_create_host' do
              normalized_host = mock('Normalized Host')
              db_manager.stub(:normalize_host).with(session).and_return(normalized_host)
              # stub report_vuln so its use of find_or_create_host and normalize_host doesn't interfere.
              db_manager.stub(:report_vuln)

              db_manager.should_receive(:find_or_create_host).with(
                  hash_including(
                      :host => normalized_host
                  )
              ).and_return(host)

              report_session
            end

            context 'with session responds to arch' do
              let(:arch) do
                FactoryGirl.generate :mdm_host_arch
              end

              before(:each) do
                session.stub(:arch => arch)
              end

              it 'should pass :arch to #find_or_create_host' do
                db_manager.should_receive(:find_or_create_host).with(
                    hash_including(
                        :arch => arch
                    )
                ).and_call_original

                report_session
              end
            end

            context 'without session responds to arch' do
              it 'should not pass :arch to #find_or_create_host' do
                db_manager.should_receive(:find_or_create_host).with(
                    hash_excluding(
                        :arch
                    )
                ).and_call_original

                report_session
              end
            end

            it 'should create an Mdm::Session' do
              expect {
                report_session
              }.to change(Mdm::Session, :count).by(1)
            end

            it { should be_an Mdm::Session }

            it 'should set session.db_record to created Mdm::Session' do
              mdm_session = report_session

              session.db_record.should == mdm_session
            end

            context 'with session.via_exploit' do
              it 'should create session.via_exploit module' do
                framework.modules.should_receive(:create).with(session.via_exploit).and_call_original

                report_session
              end

              it 'should create Mdm::Vuln' do
                expect {
                  report_session
                }.to change(Mdm::Vuln, :count).by(1)
              end

              context 'created Mdm::Vuln' do
                let(:mdm_session) do
                  Mdm::Session.last
                end

                let(:rport) do
                  nil
                end

                before(:each) do
                  Timecop.freeze

                  session.exploit_datastore['RPORT'] = rport

                  report_session
                end

                after(:each) do
                  Timecop.return
                end

                subject(:vuln) do
                  Mdm::Vuln.last
                end

                its(:host) { should == Mdm::Host.last }
                its(:refs) { should == [] }
                its(:exploited_at) { should be_within(1.second).of(Time.now.utc) }

                context "with session.via_exploit 'exploit/multi/handler'" do
                  context "with session.exploit_datastore['ParentModule']" do
                    its(:info) { should == "Exploited by #{parent_module_fullname} to create Session #{mdm_session.id}" }
                    its(:name) { should == parent_module_name }
                  end
                end

                context "without session.via_exploit 'exploit/multi/handler'" do
                  let(:reference_name) do
                    'windows/smb/ms08_067_netapi'
                  end

                  before(:each) do
                    path = File.join(
                        parent_path,
                        'exploits',
                        "#{reference_name}.rb"
                    )
                    type = 'exploit'

                    # fake cache data for ParentModule so it can be loaded
                    framework.modules.send(
                        :module_info_by_path=,
                        {
                            path =>
                                {
                                    :parent_path => parent_path,
                                    :reference_name => reference_name,
                                    :type => type,
                                }
                        }
                    )

                    session.via_exploit = "#{type}/#{reference_name}"
                  end

                  its(:info) { should == "Exploited by #{session.via_exploit} to create Session #{mdm_session.id}"}
                  its(:name) { should == reference_name }
                end

                context 'with RPORT' do
                  let(:rport) do
                    # use service.port instead of having service use rport so
                    # that service is forced to exist before call to
                    # report_service, which happens right after using rport in
                    # outer context's before(:each)
                    service.port
                  end

                  let(:service) do
                    FactoryGirl.create(
                        :mdm_service,
                        :host => host
                    )
                  end

                  its(:service) { should == service }
                end

                context 'without RPORT' do
                  its(:service) { should be_nil }
                end
              end

              context 'created Mdm::ExploitAttempt' do
                let(:rport) do
                  nil
                end

                before(:each) do
                  Timecop.freeze

                  session.exploit_datastore['RPORT'] = rport

                  report_session
                end

                after(:each) do
                  Timecop.return
                end

                subject(:exploit_attempt) do
                  Mdm::ExploitAttempt.last
                end

                its(:attempted_at) { should be_within(1.second).of(Time.now.utc) }
                # @todo https://www.pivotaltracker.com/story/show/48362615
                its(:session_id) { should == Mdm::Session.last.id }
                its(:exploited) { should == true }
                # @todo https://www.pivotaltracker.com/story/show/48362615
                its(:vuln_id) { should == Mdm::Vuln.last.id }

                context "with session.via_exploit 'exploit/multi/handler'" do
                  context "with session.datastore['ParentModule']" do
                    its(:module) { should == parent_module_fullname }
                  end
                end

                context "without session.via_exploit 'exploit/multi/handler'" do
                  before(:each) do
                    session.via_exploit = parent_module_fullname
                  end

                  its(:module) { should == session.via_exploit }
                end
              end
            end

            context 'returned Mdm::Session' do
              before(:each) do
                Timecop.freeze
              end

              after(:each) do
                Timecop.return
              end

              subject(:mdm_session) do
                report_session
              end

              #
              # Ensure session has attributes present so its on mdm_session are
              # not just comparing nils.
              #

              it 'should have session.info present' do
                session.info.should be_present
              end

              it 'should have session.sid present' do
                session.sid.should be_present
              end

              it 'should have session.platform present' do
                session.platform.should be_present
              end

              it 'should have session.type present' do
                session.type.should be_present
              end

              it 'should have session.via_exploit present' do
                session.via_exploit.should be_present
              end

              it 'should have session.via_payload present' do
                session.via_exploit.should be_present
              end

              its(:datastore) { should == session.exploit_datastore.to_h }
              its(:desc) { should == session.info }
              its(:host_id) { should == Mdm::Host.last.id }
              its(:last_seen) { should be_within(1.second).of(Time.now.utc) }
              its(:local_id) { should == session.sid }
              its(:opened_at) { should be_within(1.second).of(Time.now.utc) }
              its(:platform) { should == session.platform }
              its(:routes) { should == [] }
              its(:stype) { should == session.type }
              its(:via_payload) { should == session.via_payload }

              context "with session.via_exploit 'exploit/multi/handler'" do
                it "should have session.via_exploit of 'exploit/multi/handler'" do
                  session.via_exploit.should == 'exploit/multi/handler'
                end

                context "with session.exploit_datastore['ParentModule']" do
                  it "should have session.exploit_datastore['ParentModule']" do
                    session.exploit_datastore['ParentModule'].should_not be_nil
                  end

                  its(:via_exploit) { should == parent_module_fullname }
                end
              end

              context "without session.via_exploit 'exploit/multi/handler'" do
                before(:each) do
                  reference_name = 'windows/smb/ms08_067_netapi'
                  path = File.join(
                      parent_path,
                      'exploits',
                      "#{reference_name}.rb"
                  )
                  type = 'exploit'

                  # fake cache data for ParentModule so it can be loaded
                  framework.modules.send(
                      :module_info_by_path=,
                      {
                          path =>
                              {
                                  :parent_path => parent_path,
                                  :reference_name => reference_name,
                                  :type => type,
                              }
                      }
                  )

                  session.via_exploit = "#{type}/#{reference_name}"
                end

                it "should not have session.via_exploit of 'exploit/multi/handler'" do
                  session.via_exploit.should_not == 'exploit/multi/handler'
                end

                its(:via_exploit) { should == session.via_exploit }
              end
            end
          end
        end

        context 'without Msf::Session' do
          let(:session) do
            mock('Not a Msf::Session')
          end

          it 'should raise ArgumentError' do
            expect {
              report_session
            }.to raise_error(ArgumentError, "Invalid :session, expected Msf::Session")
          end
        end
      end

      context 'without :session' do
        context 'with :host' do
          before(:each) do
            options[:host] = host
          end

          context 'with Mdm::Host' do
            let(:host) do
              FactoryGirl.create(:mdm_host)
            end

            context 'created Mdm::Session' do
              let(:closed_at) do
                nil
              end

              let(:close_reason) do
                'Closed because...'
              end

              let(:description) do
                'Session Description'
              end

              let(:exploit_full_name) do
                'exploit/windows/smb/ms08_067_netapi'
              end

              let(:last_seen) do
                nil
              end

              let(:opened_at) do
                Time.now.utc - 5.minutes
              end

              let(:payload_full_name) do
                'payload/singles/windows/metsvc_reverse_tcp'
              end

              let(:platform) do
                'Host Platform'
              end

              let(:routes) do
                nil
              end

              let(:session_type) do
                'Session Type'
              end

              before(:each) do
                options[:closed_at] = closed_at
                options[:close_reason] = close_reason
                options[:desc] = description
                options[:last_seen] = last_seen
                options[:opened_at] = opened_at
                options[:platform] = platform
                options[:routes] = routes
                options[:stype] = session_type
                options[:via_payload] = payload_full_name
                options[:via_exploit] = exploit_full_name
              end

              subject(:mdm_session) do
                report_session
              end

              its(:close_reason) { should == close_reason }
              its(:desc) { should == description }
              its(:host) { should == host }
              its(:platform) { should == platform }
              its(:stype) { should == session_type }
              its(:via_exploit) { should == exploit_full_name }
              its(:via_payload) { should == payload_full_name }

              context 'with :last_seen' do
                let(:last_seen) do
                  opened_at
                end

                its(:last_seen) { should == last_seen }
              end

              context 'with :closed_at' do
                let(:closed_at) do
                  opened_at + 1.minute
                end

                its(:closed_at) { should == closed_at }
              end

              context 'without :closed_at' do
                its(:closed_at) { should == nil }
              end

              context 'without :last_seen' do
                context 'with :closed_at' do
                  let(:closed_at) do
                    opened_at + 1.minute
                  end

                  its(:last_seen) { should == closed_at }
                end

                context 'without :closed_at' do
                  its(:last_seen) { should be_nil }
                end
              end

              context 'with :routes' do
                let(:routes) do
                  FactoryGirl.build_list(
                      :mdm_route,
                      1,
                      :session => nil
                  )
                end

                its(:routes) { should == routes }
              end

              context 'without :routes' do
                its(:routes) { should == [] }
              end
            end
          end

          context 'without Mdm::Host' do
            let(:host) do
              '192.168.0.1'
            end

            it 'should raise ArgumentError' do
              expect {
                report_session
              }.to raise_error(ArgumentError, "Invalid :host, expected Host object")
            end
          end
        end

        context 'without :host' do
          it 'should raise ArgumentError' do
            expect {
              report_session
            }.to raise_error(ArgumentError)
          end
        end
      end
    end

    context 'without active' do
      let(:active) do
        false
      end

      it { should be_nil }

      it 'should not create a connection' do
        # 1st time for with_established_connection
        ActiveRecord::Base.connection_pool.should_receive(:with_connection).once

        report_session
      end
    end
  end

  context '#search_modules' do
    include_context 'database cleaner'
    include_context 'database seeds'

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
