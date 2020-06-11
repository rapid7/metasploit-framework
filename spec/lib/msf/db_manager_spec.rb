#
# Specs
#

require 'spec_helper'

#
# Project
#

require 'metasploit/framework/database'
require 'msf/core'

RSpec.describe Msf::DBManager do
  include_context 'Msf::DBManager'

  subject do
    db_manager
  end

  it_should_behave_like 'Msf::DBManager::Adapter'
  it_should_behave_like 'Msf::DBManager::Client'
  it_should_behave_like 'Msf::DBManager::Connection'
  it_should_behave_like 'Msf::DBManager::Cred'
  it_should_behave_like 'Msf::DBManager::Event'
  it_should_behave_like 'Msf::DBManager::ExploitAttempt'
  it_should_behave_like 'Msf::DBManager::ExploitedHost'
  it_should_behave_like 'Msf::DBManager::Host'
  it_should_behave_like 'Msf::DBManager::HostDetail'
  it_should_behave_like 'Msf::DBManager::HostTag'
  it_should_behave_like 'Msf::DBManager::IPAddress'
  it_should_behave_like 'Msf::DBManager::Import'
  it_should_behave_like 'Msf::DBManager::Loot'
  it_should_behave_like 'Msf::DBManager::Migration'
  it_should_behave_like 'Msf::DBManager::ModuleCache'
  it_should_behave_like 'Msf::DBManager::Note'
  it_should_behave_like 'Msf::DBManager::Ref'
  it_should_behave_like 'Msf::DBManager::Report'
  it_should_behave_like 'Msf::DBManager::Route'
  it_should_behave_like 'Msf::DBManager::Service'
  it_should_behave_like 'Msf::DBManager::Session'
  it_should_behave_like 'Msf::DBManager::SessionEvent'
  it_should_behave_like 'Msf::DBManager::Task'
  it_should_behave_like 'Msf::DBManager::Vuln'
  it_should_behave_like 'Msf::DBManager::VulnAttempt'
  it_should_behave_like 'Msf::DBManager::VulnDetail'
  it_should_behave_like 'Msf::DBManager::WMAP'
  it_should_behave_like 'Msf::DBManager::Web'
  it_should_behave_like 'Msf::DBManager::Workspace'

  # Not implemented in remote data service
  unless ENV['REMOTE_DB']
    it { is_expected.to respond_to :check }
    it { is_expected.to respond_to :error }
    it { is_expected.to respond_to :service_name_map }
  end

end
