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
	include_context 'Msf::Simple::Framework'

	subject(:db_manager) do
		framework.db
	end

	it_should_behave_like 'Msf::DBManager::ImportMsfXml'
end
