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

  it_should_behave_like 'Msf::DBManager::Client'
  it_should_behave_like 'Msf::DBManager::Cred'
  it_should_behave_like 'Msf::DBManager::Event'
  it_should_behave_like 'Msf::DBManager::ExploitAttempt'
  it_should_behave_like 'Msf::DBManager::ExploitedHost'
  it_should_behave_like 'Msf::DBManager::Host'
  it_should_behave_like 'Msf::DBManager::HostDetail'
  it_should_behave_like 'Msf::DBManager::HostTag'
  it_should_behave_like 'Msf::DBManager::IPAddress'
  it_should_behave_like 'Msf::DBManager::Import'
  it_should_behave_like 'Msf::DBManager::ImportMsfXml'
  it_should_behave_like 'Msf::DBManager::Loot'
  it_should_behave_like 'Msf::DBManager::Migration'
  it_should_behave_like 'Msf::DBManager::ModuleCache'
  it_should_behave_like 'Msf::DBManager::Note'
  it_should_behave_like 'Msf::DBManager::Ref'
  it_should_behave_like 'Msf::DBManager::Report'
  it_should_behave_like 'Msf::DBManager::Service'
  it_should_behave_like 'Msf::DBManager::Session'
  it_should_behave_like 'Msf::DBManager::SessionEvent'
  it_should_behave_like 'Msf::DBManager::Sink'
  it_should_behave_like 'Msf::DBManager::Task'
  it_should_behave_like 'Msf::DBManager::Vuln'
  it_should_behave_like 'Msf::DBManager::VulnDetail'
  it_should_behave_like 'Msf::DBManager::WMAP'
  it_should_behave_like 'Msf::DBManager::Workspace'

  context 'CONSTANTS' do
    context 'ADAPTER' do
      subject(:adapter) {
        described_class::ADAPTER
      }

      it { is_expected.to eq('postgresql') }
    end
  end

  it { is_expected.to respond_to :active }

  context '#add_rails_engine_migration_paths' do
    def add_rails_engine_migration_paths
      db_manager.add_rails_engine_migration_paths
    end

    it 'should not add duplicate paths to ActiveRecord::Migrator.migrations_paths' do
      add_rails_engine_migration_paths

      expect {
        add_rails_engine_migration_paths
      }.to_not change {
        ActiveRecord::Migrator.migrations_paths.length
      }

      ActiveRecord::Migrator.migrations_paths.uniq.should == ActiveRecord::Migrator.migrations_paths
    end
  end

  it { is_expected.to respond_to :after_establish_connection }
  it { is_expected.to respond_to :check }
  it { is_expected.to respond_to :connect }
  it { is_expected.to respond_to :connection_established? }
  it { is_expected.to respond_to :create_db }
  it { is_expected.to respond_to :disconnect }
  it { is_expected.to respond_to :driver }
  it { is_expected.to respond_to :drivers }
  it { is_expected.to respond_to :drivers= }
  it { is_expected.to respond_to :error }
  it { is_expected.to respond_to :initialize_adapter }
  it { is_expected.to respond_to :initialize_database_support }
  it { is_expected.to respond_to :report_session_route }
  it { is_expected.to respond_to :report_session_route_remove }
  it { is_expected.to respond_to :report_vuln_attempt }
  it { is_expected.to respond_to :report_web_form }
  it { is_expected.to respond_to :report_web_page }
  it { is_expected.to respond_to :report_web_site }
  it { is_expected.to respond_to :report_web_vuln }
  it { is_expected.to respond_to :service_name_map }
  it { is_expected.to respond_to :usable }
  it { is_expected.to respond_to :usable= }
  it { is_expected.to respond_to :warn_about_rubies }
end
