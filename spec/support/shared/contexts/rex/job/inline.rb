RSpec.shared_context 'Rex::Job#start run inline' do
  # Intercepts calls to Rex::Job objects, and ensures that async rex jobs are immediately run inline instead of having
  # their execution deferred until later. This ensures that Jobs deterministically complete during a test run.
  def run_rex_jobs_inline!
    allow_any_instance_of(Rex::Job).to receive(:start).and_wrap_original do |original_method, original_async_value|
      original_receiver = original_method.receiver
      ctx = original_receiver.ctx
      if ctx.first.is_a?(Msf::Module)
        mod = ctx.first
        mod.print_status("Running rex job #{original_receiver.jid} inline")
      end
      expect(original_async_value).to be(true)
      new_async_value = false
      original_method.call(new_async_value)
    end
  end
end
