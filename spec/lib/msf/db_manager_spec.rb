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

      after(:each) do
        ActiveRecord::Base.remove_connection
      end

      it { should be_valid }
    end
  end
end
