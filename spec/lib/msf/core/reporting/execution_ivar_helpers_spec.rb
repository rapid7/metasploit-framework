# frozen_string_literal: true

require 'spec_helper'

# Direct unit coverage for the +@api private+ ivar helpers added by
# the reporting refactor. Two pairs/trios are exercised here:
#
#   * +mark_exception_recorded+ / +exception_recorded?+ — dedup flag
#     on exception objects so the same exception is not persisted
#     twice when it bubbles through multiple rescue layers.
#   * +mark_module_unhandled_exception+ /
#     +clear_module_unhandled_exception+ /
#     +module_unhandled_exception?+ — flag on the module instance
#     consulted by the simple wrappers to decide between
#     +expected_failure+ and +unhandled_exception+ terminal statuses.
RSpec.describe Msf::Reporting::Execution, 'ivar helpers' do
  describe '.mark_exception_recorded / .exception_recorded?' do
    let(:exception) { StandardError.new('boom') }

    it 'returns false for a fresh exception' do
      expect(described_class.exception_recorded?(exception)).to be(false)
    end

    it 'returns true after the exception has been marked' do
      described_class.mark_exception_recorded(exception)
      expect(described_class.exception_recorded?(exception)).to be(true)
    end

    it 'sets the documented ivar' do
      described_class.mark_exception_recorded(exception)
      expect(
        exception.instance_variable_get(described_class::RECORDED_EXCEPTION_IVAR)
      ).to be(true)
    end

    it 'is idempotent across repeated marks' do
      described_class.mark_exception_recorded(exception)
      described_class.mark_exception_recorded(exception)
      expect(described_class.exception_recorded?(exception)).to be(true)
    end

    it 'does not leak between distinct exception objects' do
      other = RuntimeError.new('other')
      described_class.mark_exception_recorded(exception)
      expect(described_class.exception_recorded?(other)).to be(false)
    end

    it 'returns nil and swallows when instance_variable_set raises' do
      frozen = StandardError.new('frozen').freeze
      expect { described_class.mark_exception_recorded(frozen) }.not_to raise_error
      expect(described_class.exception_recorded?(frozen)).to be(false)
    end

    it 'returns false when the predicate itself raises' do
      bogus = Object.new
      allow(bogus).to receive(:instance_variable_defined?).and_raise(StandardError)
      expect(described_class.exception_recorded?(bogus)).to be(false)
    end
  end

  describe '.mark_module_unhandled_exception / .module_unhandled_exception? / .clear_module_unhandled_exception' do
    let(:mod) { Object.new }

    it 'returns false for a fresh module' do
      expect(described_class.module_unhandled_exception?(mod)).to be(false)
    end

    it 'returns true after the module has been marked' do
      described_class.mark_module_unhandled_exception(mod)
      expect(described_class.module_unhandled_exception?(mod)).to be(true)
    end

    it 'sets the documented ivar on the module instance' do
      described_class.mark_module_unhandled_exception(mod)
      expect(
        mod.instance_variable_get(described_class::UNHANDLED_EXCEPTION_IVAR)
      ).to be(true)
    end

    it 'returns false again after the flag is cleared' do
      described_class.mark_module_unhandled_exception(mod)
      described_class.clear_module_unhandled_exception(mod)
      expect(described_class.module_unhandled_exception?(mod)).to be(false)
    end

    it 'removes the ivar on clear so the module is indistinguishable from a fresh instance' do
      described_class.mark_module_unhandled_exception(mod)
      described_class.clear_module_unhandled_exception(mod)
      expect(
        mod.instance_variable_defined?(described_class::UNHANDLED_EXCEPTION_IVAR)
      ).to be(false)
    end

    it 'clear is a no-op when the flag was never set' do
      expect { described_class.clear_module_unhandled_exception(mod) }.not_to raise_error
      expect(described_class.module_unhandled_exception?(mod)).to be(false)
    end

    it 'clear handles nil modules without raising' do
      expect { described_class.clear_module_unhandled_exception(nil) }.not_to raise_error
    end

    it 'predicate returns false for a nil module' do
      expect(described_class.module_unhandled_exception?(nil)).to be(false)
    end

    it 'does not leak between distinct module instances' do
      other = Object.new
      described_class.mark_module_unhandled_exception(mod)
      expect(described_class.module_unhandled_exception?(other)).to be(false)
    end

    it 'mark swallows errors raised by instance_variable_set' do
      frozen = Object.new.freeze
      expect { described_class.mark_module_unhandled_exception(frozen) }.not_to raise_error
      expect(described_class.module_unhandled_exception?(frozen)).to be(false)
    end

    it 'clear swallows errors raised by remove_instance_variable' do
      bogus = Object.new
      allow(bogus).to receive(:instance_variable_defined?).and_return(true)
      allow(bogus).to receive(:remove_instance_variable).and_raise(StandardError)
      expect { described_class.clear_module_unhandled_exception(bogus) }.not_to raise_error
    end

    it 'predicate returns false when introspection raises' do
      bogus = Object.new
      allow(bogus).to receive(:instance_variable_defined?).and_raise(StandardError)
      expect(described_class.module_unhandled_exception?(bogus)).to be(false)
    end

    it 'a marked-then-cleared module can be re-marked' do
      described_class.mark_module_unhandled_exception(mod)
      described_class.clear_module_unhandled_exception(mod)
      described_class.mark_module_unhandled_exception(mod)
      expect(described_class.module_unhandled_exception?(mod)).to be(true)
    end
  end
end
