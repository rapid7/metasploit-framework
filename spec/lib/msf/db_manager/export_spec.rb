require 'spec_helper'

require 'msf/core/db_export'

describe Msf::DBManager::Export do
	include_context 'Msf::DBManager'

	subject(:export) do
		described_class.new(workspace)
	end

	let(:active) do
		true
	end

	let(:workspace) do
		FactoryGirl.create(
				:mdm_workspace
		)
	end

	context '#extract_module_detail_info' do
		let(:report_file) do
			StringIO.new
		end

		subject(:extract_module_detail_info) do
			export.extract_module_detail_info(report_file)
		end

		context 'with Mdm::Module::Details' do
			let(:document) do
				Nokogiri::XML(report_file.string)
			end

			let(:module_detail_count) do
				2
			end

			let(:root) do
				document.root
			end

			let!(:module_details) do
				FactoryGirl.create_list(
						:mdm_module_detail,
				    module_detail_count
				)
			end

			before(:each) do
				report_file.write("<root>")
				extract_module_detail_info
				report_file.write("</root>")
			end

			it 'should have module_detail tag for each Mdm::Module::Detail' do
				nodes = root.xpath('module_detail')

				nodes.length.should == module_detail_count
			end

			context 'module_detail' do
				let(:module_detail) do
					module_details.first
				end

				subject(:module_detail_node) do
					root.at_xpath('module_detail')
				end

				it_should_behave_like 'Msf::DBManager::Export#extract_module_detail_info module_detail child', 'description'

				context '/disclosure-date' do
					it 'should have Mdm::Module::Detail#disclosure_date present' do
						module_detail.disclosure_date.should be_present
					end

					it 'should have Mdm::Module::Detail#disclosure_date from disclosure-date content' do
						node = module_detail_node.at_xpath('disclosure-date')

						Date.parse(node.content).should == module_detail.disclosure_date
					end
				end

				it_should_behave_like 'Msf::DBManager::Export#extract_module_detail_info module_detail child', 'file'
				it_should_behave_like 'Msf::DBManager::Export#extract_module_detail_info module_detail child', 'fullname'
				it_should_behave_like 'Msf::DBManager::Export#extract_module_detail_info module_detail child', 'license'
				it_should_behave_like 'Msf::DBManager::Export#extract_module_detail_info module_detail child', 'mtime'
				it_should_behave_like 'Msf::DBManager::Export#extract_module_detail_info module_detail child', 'mtype'
				it_should_behave_like 'Msf::DBManager::Export#extract_module_detail_info module_detail child', 'name'
				it_should_behave_like 'Msf::DBManager::Export#extract_module_detail_info module_detail child', 'privileged'
				it_should_behave_like 'Msf::DBManager::Export#extract_module_detail_info module_detail child', 'rank'
				it_should_behave_like 'Msf::DBManager::Export#extract_module_detail_info module_detail child', 'refname'

				# @todo https://www.pivotaltracker.com/story/show/48451001
			end
		end

		context 'without Mdm::Module::Details' do
			it 'should not write anything to report_file' do
				extract_module_detail_info

				report_file.string.should be_empty
			end
		end
	end
end