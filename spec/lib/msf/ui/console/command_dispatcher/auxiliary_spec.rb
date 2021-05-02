require 'spec_helper'


RSpec.describe Msf::Ui::Console::CommandDispatcher::Auxiliary do
  include_context 'Msf::DBManager'
  include_context 'Msf::UIDriver'

  subject(:aux) do
    described_class.new(driver)
  end

  describe "#cmd_run" do
  end

  describe "#cmd_rerun" do
  end

  describe "#cmd_exploit" do
  end

  describe "#cmd_reload" do
  end
end
