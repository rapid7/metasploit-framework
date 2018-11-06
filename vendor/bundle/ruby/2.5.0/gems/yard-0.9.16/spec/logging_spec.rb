# frozen_string_literal: true

RSpec.describe YARD::Logger do
  describe "#show_backtraces" do
    it "is true if debug level is on" do
      log.show_backtraces = true
      log.enter_level(Logger::DEBUG) do
        log.show_backtraces = false
        expect(log.show_backtraces).to be true
      end
      expect(log.show_backtraces).to be false
    end
  end

  describe "#backtrace" do
    before { log.show_backtraces = true }
    after  { log.show_backtraces = false }

    it "logs backtrace in error by default" do
      expect(log).to receive(:error).with("RuntimeError: foo")
      expect(log).to receive(:error).with("Stack trace:\n\tline1\n\tline2\n")
      exc = RuntimeError.new("foo")
      exc.set_backtrace(['line1', 'line2'])
      log.enter_level(Logger::INFO) { log.backtrace(exc) }
    end

    it "allows backtrace to be entered in other modes" do
      expect(log).to receive(:warn).with("RuntimeError: foo")
      expect(log).to receive(:warn).with("Stack trace:\n\tline1\n\tline2\n")
      exc = RuntimeError.new("foo")
      exc.set_backtrace(['line1', 'line2'])
      log.enter_level(Logger::INFO) { log.backtrace(exc, :warn) }
    end
  end

  describe '#warn' do
    before  { log.warned = false }
    after   { log.warned = false }

    it 'changes #warned from false to true' do
      expect { log.warn('message') }.to change(log, :warned).from(false).to(true)
    end
  end
end
