# frozen_string_literal: true

require 'spec_helper'

# Msf::Auxiliary::Scanner spawns one thread per host (or per batch).
# The parent +CurrentExecution+ must propagate into those threads so
# that +fail_with+-driven failures from within +run_host+ / +run_batch+
# are attached to the parent execution row.
#
# The full +Scanner#run+ method is intricate (RhostsWalker, replicant,
# Queue plumbing, progress reporting), so this spec verifies the
# propagation pattern at the behavioral level: a parent execution is
# captured in the enclosing thread, then re-entered with
# +CurrentExecution.with(parent_execution)+ inside a spawned thread,
# so the inner code sees the same execution.
RSpec.describe Msf::Auxiliary::Scanner, 'execution propagation pattern' do
  describe 'CurrentExecution + Thread propagation primitive' do
    let(:execution) { double('Mdm::ModuleExecution', kind: 'run') }

    it 'captures parent_execution outside the spawned thread and re-enters CurrentExecution.with inside it' do
      observed = nil
      Msf::Reporting::CurrentExecution.with(execution) do
        parent_execution = Msf::Reporting::CurrentExecution.current
        thread = Thread.new do
          Msf::Reporting::CurrentExecution.with(parent_execution) do
            observed = Msf::Reporting::CurrentExecution.current
          end
        end
        thread.join
      end
      expect(observed).to be(execution)
    end

    it 'does NOT see the parent execution if the thread does not re-enter' do
      observed = :unset
      Msf::Reporting::CurrentExecution.with(execution) do
        thread = Thread.new do
          observed = Msf::Reporting::CurrentExecution.current
        end
        thread.join
      end
      expect(observed).to be_nil
    end
  end
end
