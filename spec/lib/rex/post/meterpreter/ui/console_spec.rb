# -*- coding:binary -*-

require 'spec_helper'
require 'rex/post/meterpreter/ui/console'

RSpec.describe Rex::Post::Meterpreter::Ui::Console do
  subject(:console) { described_class.new(nil) }

  describe '#interact_with_channel' do
    let(:history_manager) { instance_double(Rex::Ui::Text::Shell::HistoryManager) }
    let(:channel) { Object.new.extend(Rex::Post::Meterpreter::Ui::Console::InteractiveChannel) }

    before(:each) do
      console.history_manager = history_manager
      allow(channel).to receive(:interact)
      allow(channel).to receive(:reset_ui)
    end

    it 'keeps channel input out of the meterpreter history' do
      expect(history_manager).to receive(:with_context).with(name: :channel) do |&block|
        expect(channel).not_to have_received(:interact)
        block.call
      end

      console.interact_with_channel(channel)

      expect(channel).to have_received(:interact).once
    end

    it 'does not change the history context in raw mode' do
      expect(history_manager).not_to receive(:with_context)

      console.interact_with_channel(channel, raw: true)

      expect(channel).to have_received(:interact).once
    end
  end
end
