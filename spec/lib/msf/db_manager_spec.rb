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
  include_context 'database connection'

  subject(:db_manager) do
    FactoryGirl.build(:msf_db_manager)
  end

  it_should_behave_like 'Msf::DBManager::Activation'
  it_should_behave_like 'Msf::DBManager::Connection'
  it_should_behave_like 'Msf::DBManager::Import'
  it_should_behave_like 'Msf::DBManager::Search'
  it_should_behave_like 'Msf::DBManager::Session'

  context 'factories' do
    context 'msf_db_manager' do
      subject(:msf_db_manager) do
        FactoryGirl.build(:msf_db_manager)
      end

      # DBManager must supply its own connections
      around(:each) do |example|
        without_established_connection do
          example.run
        end
      end

      it { should be_valid }
    end
  end
end
