module Msf
  module RPC
    class RpcFrameworkEventSubscriber
      def initialize(job_status_tracker)
        @job_status_tracker = job_status_tracker
      end

      def on_module_setup(mod)
        $stderr.puts "Made it to the on_module_setup #{mod[:run_uuid]}"
        @job_status_tracker.start(mod[:run_uuid])
      end

      def on_module_run(mod, result)
        $stderr.puts "Made it to the on_module_run #{mod[:run_uuid]}"
        @job_status_tracker.completed(mod[:run_uuid], result, mod)
      end
    end
  end
end
