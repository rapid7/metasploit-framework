RSpec.shared_examples_for 'Msf::DBManager::Session' do
  it { is_expected.to respond_to :get_session }

  if ENV['REMOTE_DB']
    before {skip("Awaiting sessions port")}
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

      context 'with :session' do
        before(:example) do
          options[:session] = session
        end

        context 'with Msf::Session' do
          include_context 'Metasploit::Framework::Spec::Constants cleaner'

          let(:exploit_datastore) do
            Msf::ModuleDataStore.new(module_instance).tap do |datastore|
              datastore['ParentModule'] = parent_module_fullname

              remote_port = rand(2 ** 16 - 1)
              datastore['RPORT'] = remote_port
            end
          end

          let(:host) do
            FactoryBot.create(:mdm_host, :workspace => session_workspace)
          end

          let(:module_instance) do
            name = 'multi/handler'

            d = double(
                'Msf::Exploit',
                user_data: user_data,
                fullname: "exploit/#{name}",
                framework: framework,
                name: name
            )
            d
          end

          let(:options_workspace) do
            FactoryBot.create(:mdm_workspace)
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
              session.exploit = module_instance
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

              attr_accessor :arch
              attr_accessor :exploit
              attr_accessor :datastore
              attr_accessor :platform
              attr_accessor :type
              attr_accessor :via_exploit
              attr_accessor :via_payload
            end
          end

          let(:session_workspace) do
            FactoryBot.create(:mdm_workspace)
          end

          before(:example) do
            reference_name = 'multi/handler'
            path = File.join(parent_path, 'exploits', reference_name)

            # fake cache data for exploit/multi/handler so it can be loaded
            framework.modules.send(
                :module_info_by_path=,
                {
                    path =>
                        {
                            :parent_path => parent_path,
                            :reference_name => reference_name,
                            :type => 'exploit',
                        }
                }
            )

            FactoryBot.create(
                :mdm_module_detail,
                :fullname => parent_module_fullname,
                :name => parent_module_name
            )
          end

          context 'with a run_id in user_data' do
            before(:example) do
              allow(db_manager).to receive(:create_match_for_vuln).and_return(nil)
            end

            let(:match_set) do
              FactoryBot.create(:automatic_exploitation_match_set, user: session_workspace.owner,workspace:session_workspace)
            end

            let(:run) do
              FactoryBot.create(:automatic_exploitation_run, workspace: session_workspace, match_set_id: match_set.id)
            end

            let(:user_data) do
              {
                run_id: run.id
              }
            end

            context 'with :workspace' do
              before(:example) do
                options[:workspace] = options_workspace
              end

              it 'should not find workspace from session' do
                expect(db_manager).not_to receive(:find_workspace)

                expect { report_session }.to change(Mdm::Vuln, :count).by(1)
              end
            end

            context 'without :workspace' do
              it 'should find workspace from session' do
                expect(db_manager).to receive(:find_workspace).with(session.workspace).and_call_original

                report_session
              end

              it 'should pass session.workspace to #find_or_create_host' do
                expect(db_manager).to receive(:find_or_create_host).with(
                  hash_including(
                    :workspace => session_workspace
                  )
                ).and_return(host)

                expect { report_session }.to change(Mdm::Vuln, :count).by(1)
              end
            end

            context 'with workspace from either :workspace or session' do

              context 'with session responds to arch' do
                let(:arch) do
                  FactoryBot.generate :mdm_host_arch
                end

                before(:example) do
                  allow(session).to receive(:arch).and_return(arch)
                end

                it 'should pass :arch to #find_or_create_host' do
                  expect(db_manager).to receive(:find_or_create_host).with(
                    hash_including(
                      :arch => arch
                    )
                  ).and_call_original

                  expect { report_session }.to change(Mdm::Vuln, :count).by(1)
                end
              end

              context 'without session responds to arch' do
                it 'should not pass :arch to #find_or_create_host' do
                  expect(db_manager).to receive(:find_or_create_host).with(
                    hash_excluding(
                      :arch
                    )
                  ).and_call_original

                  expect { report_session }.to change(Mdm::Vuln, :count).by(1)
                end
              end

              it 'should create an Mdm::Session' do
                expect {
                  report_session
                }.to change(Mdm::Session, :count).by(1)
              end

              it { is_expected.to be_an Mdm::Session }

              it 'should set session.db_record to created Mdm::Session' do
                mdm_session = report_session

                expect(session.db_record).to eq mdm_session
              end

              context 'with session.via_exploit' do

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

                  before(:example) do
                    Timecop.freeze

                    session.exploit_datastore['RPORT'] = rport

                    report_session
                  end

                  after(:example) do
                    Timecop.return
                  end

                  subject(:vuln) do
                    Mdm::Vuln.last
                  end

                  it { expect(subject.host).to eq(Mdm::Host.last) }
                  it { expect(subject.refs).to eq([]) }
                  it { expect(subject.exploited_at).to be_within(1.second).of(Time.now.utc) }

                  context "with session.via_exploit 'exploit/multi/handler'" do
                    context "with session.exploit_datastore['ParentModule']" do
                      it { expect(subject.info).to eq("Exploited by #{parent_module_fullname} to create Session #{mdm_session.id}") }
                      it { expect(subject.name).to eq(parent_module_name) }
                    end
                  end

                  context "without session.via_exploit 'exploit/multi/handler'" do
                    let(:reference_name) do
                      'windows/smb/ms08_067_netapi'
                    end

                    before(:example) do
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

                    it { expect(subject.info).to eq("Exploited by #{session.via_exploit} to create Session #{mdm_session.id}") }
                    it { expect(subject.name).to eq(reference_name) }
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
                      FactoryBot.create(
                        :mdm_service,
                        :host => host
                      )
                    end

                    it { expect(subject.service).to eq(service) }
                  end

                  context 'without RPORT' do
                    it { expect(subject.service).to be_nil }
                  end
                end

                context 'created Mdm::ExploitAttempt' do
                  let(:rport) do
                    nil
                  end

                  before(:example) do
                    Timecop.freeze

                    session.exploit_datastore['RPORT'] = rport

                    report_session
                  end

                  after(:example) do
                    Timecop.return
                  end

                  subject(:exploit_attempt) do
                    Mdm::ExploitAttempt.last
                  end

                  it { expect(subject.attempted_at).to be_within(1.second).of(Time.now.utc) }
                  # @todo https://www.pivotaltracker.com/story/show/48362615
                  it { expect(subject.session_id).to eq(Mdm::Session.last.id) }
                  it { expect(subject.exploited).to be_truthy }
                  # @todo https://www.pivotaltracker.com/story/show/48362615
                  it { expect(subject.vuln_id).to eq(Mdm::Vuln.last.id) }

                  context "with session.via_exploit 'exploit/multi/handler'" do
                    context "with session.datastore['ParentModule']" do
                      it { expect(subject.module).to eq(parent_module_fullname) }
                    end
                  end

                  context "without session.via_exploit 'exploit/multi/handler'" do
                    before(:example) do
                      session.via_exploit = parent_module_fullname
                    end

                    it { expect(subject.module).to eq(session.via_exploit) }
                  end
                end
              end

              context 'returned Mdm::Session' do
                before(:example) do
                  Timecop.freeze
                end

                after(:example) do
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
                  expect(session.info).to be_present
                end

                it 'should have session.sid present' do
                  expect(session.sid).to be_present
                end

                it 'should have session.platform present' do
                  expect(session.platform).to be_present
                end

                it 'should have session.type present' do
                  expect(session.type).to be_present
                end

                it 'should have session.via_exploit present' do
                  expect(session.via_exploit).to be_present
                end

                it 'should have session.via_payload present' do
                  expect(session.via_exploit).to be_present
                end

                it { expect(subject.datastore).to eq(session.exploit_datastore.to_h) }
                it { expect(subject.desc).to eq(session.info) }
                it { expect(subject.host_id).to eq(Mdm::Host.last.id) }
                it { expect(subject.last_seen).to be_within(1.second).of(Time.now.utc) }
                it { expect(subject.local_id).to eq(session.sid) }
                it { expect(subject.opened_at).to be_within(1.second).of(Time.now.utc) }
                it { expect(subject.platform).to eq(session.session_type) }
                it { expect(subject.routes).to eq([]) }
                it { expect(subject.stype).to eq(session.type) }
                it { expect(subject.via_payload).to eq(session.via_payload) }

                context "with session.via_exploit 'exploit/multi/handler'" do
                  it "should have session.via_exploit of 'exploit/multi/handler'" do
                    expect(session.via_exploit).to eq 'exploit/multi/handler'
                  end

                  context "with session.exploit_datastore['ParentModule']" do
                    it "should have session.exploit_datastore['ParentModule']" do
                      expect(session.exploit_datastore['ParentModule']).not_to be_nil
                    end

                    it { expect(subject.via_exploit).to eq(parent_module_fullname) }
                  end
                end

                context "without session.via_exploit 'exploit/multi/handler'" do
                  before(:example) do
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
                    expect(session.via_exploit).not_to eq 'exploit/multi/handler'
                  end

                  it { expect(subject.via_exploit).to eq(session.via_exploit) }
                end
              end
            end
          end

          context 'without user_data' do
            let(:user_data) { nil }

            context 'with :workspace' do
              before(:example) do
                options[:workspace] = options_workspace
              end

              it 'should not find workspace from session' do
                expect(db_manager).not_to receive(:find_workspace)

                expect { report_session }.to change(Mdm::Vuln, :count).by(1)
              end
            end

            context 'without :workspace' do
              it 'should find workspace from session' do
                expect(db_manager).to receive(:find_workspace).with(session.workspace).and_call_original

                report_session
              end

              it 'should pass session.workspace to #find_or_create_host' do
                expect(db_manager).to receive(:find_or_create_host).with(
                    hash_including(
                        :workspace => session_workspace
                    )
                ).and_return(host)

                expect { report_session }.to change(Mdm::Vuln, :count).by(1)
              end
            end

            context 'with workspace from either :workspace or session' do

              context 'with session responds to arch' do
                let(:arch) do
                  FactoryBot.generate :mdm_host_arch
                end

                before(:example) do
                  allow(session).to receive(:arch).and_return(arch)
                end

                it 'should pass :arch to #find_or_create_host' do
                  expect(db_manager).to receive(:find_or_create_host).with(
                      hash_including(
                          :arch => arch
                      )
                  ).and_call_original

                  expect { report_session }.to change(Mdm::Vuln, :count).by(1)
                end
              end

              context 'without session responds to arch' do
                it 'should not pass :arch to #find_or_create_host' do
                  expect(db_manager).to receive(:find_or_create_host).with(
                      hash_excluding(
                          :arch
                      )
                  ).and_call_original

                  expect { report_session }.to change(Mdm::Vuln, :count).by(1)
                end
              end

              it 'should create an Mdm::Session' do
                expect {
                  report_session
                }.to change(Mdm::Session, :count).by(1)
              end

              it { is_expected.to be_an Mdm::Session }

              it 'should set session.db_record to created Mdm::Session' do
                mdm_session = report_session

                expect(session.db_record).to eq mdm_session
              end

              context 'with session.via_exploit' do

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

                  before(:example) do
                    Timecop.freeze

                    session.exploit_datastore['RPORT'] = rport

                    report_session
                  end

                  after(:example) do
                    Timecop.return
                  end

                  subject(:vuln) do
                    Mdm::Vuln.last
                  end

                  it { expect(subject.host).to eq(Mdm::Host.last) }
                  it { expect(subject.refs).to eq([]) }
                  it { expect(subject.exploited_at).to be_within(1.second).of(Time.now.utc) }

                  context "with session.via_exploit 'exploit/multi/handler'" do
                    context "with session.exploit_datastore['ParentModule']" do
                      it { expect(subject.info).to eq("Exploited by #{parent_module_fullname} to create Session #{mdm_session.id}") }
                      it { expect(subject.name).to eq(parent_module_name) }
                    end
                  end

                  context "without session.via_exploit 'exploit/multi/handler'" do
                    let(:reference_name) do
                      'windows/smb/ms08_067_netapi'
                    end

                    before(:example) do
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

                    it { expect(subject.info).to eq("Exploited by #{session.via_exploit} to create Session #{mdm_session.id}") }
                    it { expect(subject.name).to eq(reference_name) }
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
                      FactoryBot.create(
                          :mdm_service,
                          :host => host
                      )
                    end

                    it { expect(subject.service).to eq(service) }
                  end

                  context 'without RPORT' do
                    it { expect(subject.service).to be_nil }
                  end
                end

                context 'created Mdm::ExploitAttempt' do
                  let(:rport) do
                    nil
                  end

                  before(:example) do
                    Timecop.freeze

                    session.exploit_datastore['RPORT'] = rport

                    report_session
                  end

                  after(:example) do
                    Timecop.return
                  end

                  subject(:exploit_attempt) do
                    Mdm::ExploitAttempt.last
                  end

                  it { expect(subject.attempted_at).to be_within(1.second).of(Time.now.utc) }
                  # @todo https://www.pivotaltracker.com/story/show/48362615
                  it { expect(subject.session_id).to eq(Mdm::Session.last.id) }
                  it { expect(subject.exploited).to be_truthy }
                  # @todo https://www.pivotaltracker.com/story/show/48362615
                  it { expect(subject.vuln_id).to eq(Mdm::Vuln.last.id) }

                  context "with session.via_exploit 'exploit/multi/handler'" do
                    context "with session.datastore['ParentModule']" do
                      it { expect(subject.module).to eq(parent_module_fullname) }
                    end
                  end

                  context "without session.via_exploit 'exploit/multi/handler'" do
                    before(:example) do
                      session.via_exploit = parent_module_fullname
                    end

                    it { expect(subject.module).to eq(session.via_exploit) }
                  end
                end
              end

              context 'returned Mdm::Session' do
                before(:example) do
                  Timecop.freeze
                end

                after(:example) do
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
                  expect(session.info).to be_present
                end

                it 'should have session.sid present' do
                  expect(session.sid).to be_present
                end

                it 'should have session.platform present' do
                  expect(session.platform).to be_present
                end

                it 'should have session.type present' do
                  expect(session.type).to be_present
                end

                it 'should have session.via_exploit present' do
                  expect(session.via_exploit).to be_present
                end

                it 'should have session.via_payload present' do
                  expect(session.via_exploit).to be_present
                end

                it { expect(subject.datastore).to eq(session.exploit_datastore.to_h) }
                it { expect(subject.desc).to eq(session.info) }
                it { expect(subject.host_id).to eq(Mdm::Host.last.id) }
                it { expect(subject.last_seen).to be_within(1.second).of(Time.now.utc) }
                it { expect(subject.local_id).to eq(session.sid) }
                it { expect(subject.opened_at).to be_within(1.second).of(Time.now.utc) }
                it { expect(subject.platform).to eq(session.session_type) }
                it { expect(subject.routes).to eq([]) }
                it { expect(subject.stype).to eq(session.type) }
                it { expect(subject.via_payload).to eq(session.via_payload) }

                context "with session.via_exploit 'exploit/multi/handler'" do
                  it "should have session.via_exploit of 'exploit/multi/handler'" do
                    expect(session.via_exploit).to eq 'exploit/multi/handler'
                  end

                  context "with session.exploit_datastore['ParentModule']" do
                    it "should have session.exploit_datastore['ParentModule']" do
                      expect(session.exploit_datastore['ParentModule']).not_to be_nil
                    end

                    it { expect(subject.via_exploit).to eq(parent_module_fullname) }
                  end
                end

                context "without session.via_exploit 'exploit/multi/handler'" do
                  before(:example) do
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
                    expect(session.via_exploit).not_to eq 'exploit/multi/handler'
                  end

                  it { expect(subject.via_exploit).to eq(session.via_exploit) }
                end
              end
            end
          end
        end

        context 'without Msf::Session' do
          let(:session) do
            double('Not a Msf::Session')
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
          before(:example) do
            options[:host] = host
          end

          context 'with Mdm::Host' do
            let(:host) do
              FactoryBot.create(:mdm_host)
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

              before(:example) do
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

              it { expect(subject.close_reason).to eq(close_reason) }
              it { expect(subject.desc).to eq(description) }
              it { expect(subject.host).to eq(host) }
              it { expect(subject.platform).to eq(platform) }
              it { expect(subject.stype).to eq(session_type) }
              it { expect(subject.via_exploit).to eq(exploit_full_name) }
              it { expect(subject.via_payload).to eq(payload_full_name) }

              context 'with :last_seen' do
                let(:last_seen) do
                  opened_at
                end

                it { expect(subject.last_seen).to eq(last_seen) }
              end

              context 'with :closed_at' do
                let(:closed_at) do
                  opened_at + 1.minute
                end

                it { expect(subject.closed_at).to eq(closed_at) }
              end

              context 'without :closed_at' do
                it { expect(subject.closed_at).to be_nil }
              end

              context 'without :last_seen' do
                context 'with :closed_at' do
                  let(:closed_at) do
                    opened_at + 1.minute
                  end

                  it { expect(subject.last_seen).to eq(closed_at) }
                end

                context 'without :closed_at' do
                  it { expect(subject.last_seen).to be_nil }
                end
              end

              context 'with :routes' do
                let(:routes) do
                  FactoryBot.build_list(
                      :mdm_route,
                      1,
                      :session => nil
                  )
                end

                it { expect(subject.routes.to_a).to eq(routes) }
              end

              context 'without :routes' do
                it { expect(subject.routes).to eq([]) }
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

      it { is_expected.to be_nil }

      it 'should not create a connection' do
        expect(ActiveRecord::Base.connection_pool).not_to receive(:with_connection)

        report_session
      end
    end
  end
end
