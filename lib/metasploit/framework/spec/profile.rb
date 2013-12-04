module Metasploit::Framework::Spec::Profile
  def self.configure!
    unless @configured
      RSpec.configure do |config|
        # CPU Profiling
        if ENV['METASPLOIT_FRAMEWORK_PROFILE']
          require 'perftools'

          formatted_time = Time.now.strftime('%Y%m%d%H%M%S')
          profile_pathname = Metasploit::Framework.root.join('spec', 'profiles', formatted_time, 'suite')

          config.before(:suite) do
            profile_pathname.parent.mkpath
            PerfTools::CpuProfiler.start(profile_pathname.to_path)
          end

          config.after(:suite) do
            PerfTools::CpuProfiler.stop
            puts "Generating pdf"
            pdf_pathname = "#{profile_pathname}.pdf"
            system("bundle exec pprof.rb --pdf #{profile_pathname} > #{pdf_pathname}")
            puts "PDF saved to #{pdf_pathname}"
            system("open #{pdf_pathname}")
          end
        end
      end

      @configured = true
    end
  end
end