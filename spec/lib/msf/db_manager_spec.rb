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

	it_should_behave_like 'Msf::DBManager::Migration'
	it_should_behave_like 'Msf::DBManager::ImportMsfXml'

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
			FactoryGirl.create_list(
					:mdm_module_detail,
			    module_detail_count
			)
		end

		before(:each) do
			db_manager.stub(:migrated => migrated)
		end

		context 'with migrated' do
			let(:migrated) do
				true
			end

			let(:modules_caching) do
				false
			end

			before(:each) do
				db_manager.stub(:modules_caching => modules_caching)
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
				it 'should create a connection' do
					# in purge_all_module_details
					# in after(:each)
					ActiveRecord::Base.connection_pool.should_receive(:with_connection).twice.and_call_original

					purge_all_module_details
				end

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

	context '#remove_module_details' do
		def remove_module_details
			db_manager.remove_module_details(mtype, refname)
		end

		let(:migrated) do
			false
		end

		let(:mtype) do
			FactoryGirl.generate :mdm_module_detail_mtype
		end

		let(:refname) do
			FactoryGirl.generate :mdm_module_detail_refname
		end

		let!(:module_detail) do
			FactoryGirl.create(
					:mdm_module_detail
			)
		end

		before(:each) do
			db_manager.stub(:migrated => migrated)
		end

		context 'with migrated' do
			let(:migrated) do
				true
			end

			let!(:module_detail) do
				FactoryGirl.create(:mdm_module_detail)
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

	context '#update_all_module_details' do
		def update_all_module_details
			db_manager.update_all_module_details
		end

		let(:migrated) do
			false
		end

		before(:each) do
			db_manager.stub(:migrated => migrated)
		end

		context 'with migrated' do
			let(:migrated) do
				true
			end

			let(:modules_caching) do
				true
			end

			before(:each) do
				db_manager.stub(:modules_caching => modules_caching)
			end

			context 'with modules_caching' do
				it 'should not update module details' do
					db_manager.should_not_receive(:update_module_details)

					update_all_module_details
				end
			end

			context 'without modules_caching' do
				let(:modules_caching) do
					false
				end

				it 'should create a connection' do
					ActiveRecord::Base.connection_pool.should_receive(:with_connection).twice.and_call_original

					update_all_module_details
				end

				it 'should set framework.cache_thread to current thread and then nil around connection' do
					framework.should_receive(:cache_thread=).with(Thread.current).ordered
					ActiveRecord::Base.connection_pool.should_receive(:with_connection).ordered
					framework.should_receive(:cache_thread=).with(nil).ordered

					update_all_module_details

					ActiveRecord::Base.connection_pool.should_receive(:with_connection).ordered.and_call_original
				end

				it 'should set modules_cached to false and then true around connection' do
					db_manager.should_receive(:modules_cached=).with(false).ordered
					ActiveRecord::Base.connection_pool.should_receive(:with_connection).ordered
					db_manager.should_receive(:modules_cached=).with(true).ordered

					update_all_module_details

					ActiveRecord::Base.connection_pool.should_receive(:with_connection).ordered.and_call_original
				end

				it 'should set modules_caching to true and then false around connection' do
					db_manager.should_receive(:modules_caching=).with(true).ordered
					ActiveRecord::Base.connection_pool.should_receive(:with_connection).ordered
					db_manager.should_receive(:modules_caching=).with(false).ordered

					update_all_module_details

					ActiveRecord::Base.connection_pool.should_receive(:with_connection).ordered.and_call_original
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
						FactoryGirl.create(
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
										db_manager.should_not_receive(:update_module_details)

										update_all_module_details
									end
								end

								context 'without same Mdm::Module::Detail#mtime and File.mtime' do
									let(:modification_time) do
										# +1 as rand can return 0 and the time must be different for
										# this context.
										super() - (rand(1.day) + 1)
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
									db_manager.should_not_receive(:update_module_details)

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
				db_manager.should_not_receive(:update_module_details)

				update_all_module_details
			end
		end
	end

	context '#update_module_details' do
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

		before(:each) do
			db_manager.stub(:migrated => migrated)
		end

		context 'with migrated' do
			let(:migrated) do
				true
			end

			it 'should create connection' do
				ActiveRecord::Base.connection_pool.should_receive(:with_connection)
				ActiveRecord::Base.connection_pool.should_receive(:with_connection).and_call_original

				update_module_details
			end

			it 'should call module_to_details_hash to get Mdm::Module::Detail attributes and association attributes' do
				db_manager.should_receive(:module_to_details_hash).and_call_original

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
					FactoryGirl.generate :mdm_module_detail_privileged
				end

				let(:rank) do
					FactoryGirl.generate :mdm_module_detail_rank
				end

				let(:stance) do
					FactoryGirl.generate :mdm_module_detail_stance
				end

				before(:each) do
					db_manager.stub(
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

					before(:each) do
						update_module_details
					end

					its(:mtype) { should == module_type }
					its(:privileged) { should == privileged }
					its(:rank) { should == rank }
					its(:ready) { should == true }
					its(:refname) { should == module_reference_name }
					its(:stance) { should == stance }
				end

				context 'with :bits' do
					let(:bits) do
						[]
					end

					before(:each) do
						module_to_details_hash[:bits] = bits
					end

					context 'with :action' do
						let(:name) do
							FactoryGirl.generate :mdm_module_action_name
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

							before(:each) do
								update_module_details
							end

							its(:name) { should == name }
						end
					end

					context 'with :arch' do
						let(:name) do
							FactoryGirl.generate :mdm_module_arch_name
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

							before(:each) do
								update_module_details
							end

							its(:name) { should == name }
						end
					end

					context 'with :author' do
						let(:email) do
							FactoryGirl.generate :mdm_module_author_email
						end

						let(:name) do
							FactoryGirl.generate :mdm_module_author_name
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

							before(:each) do
								update_module_details
							end

							its(:name) { should == name }
							its(:email) { should == email }
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
							FactoryGirl.generate :mdm_module_platform_name
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

							before(:each) do
								update_module_details
							end

							its(:name) { should == name }
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
							FactoryGirl.generate :mdm_module_ref_name
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

							before(:each) do
								update_module_details
							end

							its(:name) { should == name }
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
							FactoryGirl.generate :mdm_module_target_index
						end

						let(:name) do
							FactoryGirl.generate :mdm_module_target_name
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

							before(:each) do
								update_module_details
							end

							its(:index) { should == index }
							its(:name) { should == name }
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

  context '#normalize_host' do
    context 'when passed a string' do
      context'of an ipv4 address' do
        let(:ipv4_addr) { '192.168.1.1'}
        it 'should return the same string if it is a normal valid ipv4 address' do
          db_manager.normalize_host(ipv4_addr).should == ipv4_addr
        end

        it 'should strip off trailing port numbers' do
          db_manager.normalize_host("#{ipv4_addr}:80").should == ipv4_addr
        end

        it 'should strip off trailing CIDR ranges' do
          db_manager.normalize_host("#{ipv4_addr}/24").should == ipv4_addr
        end
      end

      context 'of an ipv6 address' do
        it 'should just return a valid ipv6 address with padding' do
          ipv6_addr = '2607:f0d0:1002:51::4'
          db_manager.normalize_host(ipv6_addr).should == ipv6_addr
        end

        it 'should just return a valid ipv6 address without padding' do
          ipv6_addr = '2607:f0d0:1002:0051:0000:0000:0000:0004'
          db_manager.normalize_host(ipv6_addr).should == ipv6_addr
        end

        it 'should drop the scope off the end' do
          ipv6_addr =  '2607:f0d0:1002:51::4'
          db_manager.normalize_host("#{ipv6_addr}%16").should == ipv6_addr
        end
      end
    end

    context 'when passed an Mdm::Session' do
      it 'should return the host from the session' do
        session = FactoryGirl.create(:mdm_session)
        db_manager.normalize_host(session).should == session.host
      end
    end
  end
end
