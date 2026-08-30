require 'open3'

module Msf
  module Util
    class ServiceHelper
      def self.run_cmd(cmd, input: nil, env: {}, debug: false)
        exitstatus = 0
        err = out = ""

        $stdout.puts "run_cmd: cmd=#{cmd}, input=#{input}, env=#{env}" if debug

        Open3.popen3(env, cmd) do |stdin, stdout, stderr, wait_thr|
          stdin.puts(input) if input
          if debug
            err = stderr.read
            out = stdout.read
          end
          exitstatus = wait_thr.value.exitstatus
        end

        if exitstatus != 0
          if debug
            $stdout.puts "'#{cmd}' returned #{exitstatus}"
            $stdout.puts out
            $stdout.puts err
          end
        end

        exitstatus
      end

      def self.process_active?(pid)
        begin
          Process.kill(0, pid)
          true
        rescue Errno::ESRCH
          false
        end
      end

      def self.tail(file)
        begin
          File.readlines(file).last.to_s.strip
        rescue
          nil
        end
      end

      def self.thin_cmd(conf:, address:, port:, ssl:, ssl_key:, ssl_cert:, ssl_disable_verify:,
                        env: 'production', daemonize:, log:, pid:, tag:)
        server_opts = "--rackup #{conf} --address #{address} --port #{port}"
        ssl_opts = ssl ? "--ssl --ssl-key-file #{ssl_key} --ssl-cert-file #{ssl_cert}" : ''
        ssl_opts << ' --ssl-disable-verify' if ssl_disable_verify
        adapter_opts = "--environment #{env}"
        daemon_opts = daemonize ? "--daemonize --log #{log} --pid #{pid} --tag #{tag}" : ''
        all_opts = [server_opts, ssl_opts, adapter_opts, daemon_opts].reject(&:empty?).join(' ')

        "thin #{all_opts}"
      end
    end
  end
end
