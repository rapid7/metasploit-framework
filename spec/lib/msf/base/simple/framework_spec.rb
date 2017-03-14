require 'spec_helper'

RSpec.describe Msf::Simple::Framework do
  include_context 'Msf::Simple::Framework'

  subject do
    framework
  end

  it_should_behave_like 'Msf::Simple::Framework::ModulePaths'
end
