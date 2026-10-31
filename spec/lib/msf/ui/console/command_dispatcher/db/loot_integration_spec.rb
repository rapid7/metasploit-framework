require 'spec_helper'

RSpec.describe Msf::Ui::Console::CommandDispatcher::Db do
  include_context 'Msf::DBManager'
  include_context 'Msf::UIDriver'

  subject(:dispatcher) { described_class.new(driver) }

  let(:workspace) { framework.db.add_workspace('codex_loot_integration') }
  let(:host) { Mdm::Host.create!(workspace: workspace, address: '192.0.2.1') }
  let!(:passwd) do
    Mdm::Loot.create!(workspace: workspace, host: host, ltype: 'linux.passwd', content_type: 'text/plain', name: 'passwd-fixture.txt', path: '/tmp/codex-passwd-fixture.txt')
  end
  let!(:shadow) do
    Mdm::Loot.create!(workspace: workspace, host: host, ltype: 'linux.shadow', content_type: 'text/plain', name: 'shadow-fixture.txt', path: '/tmp/codex-shadow-fixture.txt')
  end

  before { framework.db.workspace = workspace }

  it 'lists only the requested type from PostgreSQL' do
    dispatcher.cmd_loot('-t', 'linux.passwd')
    expect(@output.join("\n")).to include('passwd-fixture.txt')
    expect(@output.join("\n")).not_to include('shadow-fixture.txt')
  end

  it 'deletes only the requested type from PostgreSQL' do
    dispatcher.cmd_loot('-d', '-t', 'linux.passwd', '192.0.2.1')
    expect(Mdm::Loot.exists?(passwd.id)).to be(false)
    expect(Mdm::Loot.exists?(shadow.id)).to be(true)
  end

  it 'does not delete records for an unmatched type' do
    dispatcher.cmd_loot('-d', '-t', 'missing.type')
    expect(Mdm::Loot.where(workspace: workspace).pluck(:id)).to match_array([passwd.id, shadow.id])
  end
end
