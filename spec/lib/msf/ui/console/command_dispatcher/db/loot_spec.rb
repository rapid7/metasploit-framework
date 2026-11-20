require 'spec_helper'

RSpec.describe Msf::Ui::Console::CommandDispatcher::Db do
  include_context 'Msf::UIDriver'

  subject(:dispatcher) { described_class.new(driver) }

  let(:framework) { double('Framework', db: db_manager) }
  let(:db_manager) { double('DBManager', active: true, workspace: 'default') }
  let(:loot) do
    double('Loot',
           id: 123, host: nil, service: nil, ltype: 'linux.passwd',
           name: 'passwd.txt', content_type: 'text/plain', info: 'Test loot', path: '/tmp/passwd.txt')
  end

  describe '#cmd_loot' do
    it 'lists all types when no type filter is specified' do
      expect(db_manager).to receive(:loots).with({ workspace: 'default', search_term: nil }).and_return([])

      dispatcher.cmd_loot
    end

    it 'filters by a single type with -t' do
      expect(db_manager).to receive(:loots).with({ workspace: 'default', search_term: nil, ltype: ['linux.passwd'] }).and_return([])

      dispatcher.cmd_loot('-t', 'linux.passwd')
    end

    it 'filters by multiple types with --type' do
      expect(db_manager).to receive(:loots).with({ workspace: 'default', search_term: nil, ltype: ['linux.passwd', 'linux.shadow'] }).and_return([])

      dispatcher.cmd_loot('--type', 'linux.passwd,linux.shadow')
    end

    it 'combines type, host and search filters' do
      expect(db_manager).to receive(:loots).with({
        workspace: 'default', search_term: 'Test loot', ltype: ['linux.passwd'], hosts: { address: ['192.0.2.1'] }
      }).and_return([])

      dispatcher.cmd_loot('-t', 'linux.passwd', '-S', 'Test loot', '192.0.2.1')
    end

    it 'shows the matching loot returned by the type query' do
      allow(db_manager).to receive(:loots).with({ workspace: 'default', search_term: nil, ltype: ['linux.passwd'] }).and_return([loot])

      dispatcher.cmd_loot('-t', 'linux.passwd')

      expect(@output.join("\n")).to include('passwd.txt')
    end

    it 'deletes only the loot returned by the type query' do
      allow(db_manager).to receive(:loots).with({ workspace: 'default', search_term: nil, ltype: ['linux.passwd'] }).and_return([loot])
      expect(db_manager).to receive(:delete_loot).with(ids: [123]).and_return([loot])

      dispatcher.cmd_loot('-d', '-t', 'linux.passwd')
    end

    it 'does not select other loot when the requested type has no matches' do
      allow(db_manager).to receive(:loots).with({ workspace: 'default', search_term: nil, ltype: ['missing.type'] }).and_return([])
      expect(db_manager).to receive(:delete_loot).with(ids: []).and_return([])

      dispatcher.cmd_loot('-d', '-t', 'missing.type')
    end

    it 'does not use the replacement type as a filter when updating loot' do
      expect(db_manager).to receive(:loots).with({ workspace: 'default', search_term: nil }).and_return([loot])
      expect(loot).to receive(:ltype=).with('replacement.type')
      allow(loot).to receive(:as_json).and_return(double('Loot attributes', symbolize_keys: { id: 123, ltype: 'replacement.type' }))
      expect(db_manager).to receive(:update_loot).with({ id: 123, ltype: 'replacement.type' })

      dispatcher.cmd_loot('-u', '-t', 'replacement.type')
    end
  end
end
