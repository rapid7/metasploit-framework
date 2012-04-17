CLEAN.include %w(coverage tmp log)

gem "rspec", "~> 1.2.9"
require 'spec/rake/spectask'

PERF_SPECS = FileList['spec/perf/*_spec.rb']
WIN_SPECS  = %w(
  spec/backends/unix_server_spec.rb
  spec/controllers/service_spec.rb
  spec/daemonizing_spec.rb
  spec/server/unix_socket_spec.rb
  spec/server/swiftiply_spec.rb
)
# HACK Event machine causes some problems when running multiple
# tests in the same VM so we split the specs in 2 before I find
# a better solution...
SPECS2     = %w(spec/server/threaded_spec.rb spec/server/tcp_spec.rb)  
SPECS      = FileList['spec/**/*_spec.rb'] - PERF_SPECS - SPECS2

def spec_task(name, specs)
  Spec::Rake::SpecTask.new(name) do |t|
    t.libs << 'lib'
    t.spec_opts = %w(-fs -c)
    t.spec_files = specs
  end
end

desc "Run all examples"
spec_task :spec, SPECS
spec_task :spec2, SPECS2
task :spec => [:compile, :spec2]

desc "Run all performance examples"
spec_task 'spec:perf', PERF_SPECS

task :check_benchmark_unit_gem do
  begin
    require 'benchmark_unit'
  rescue LoadError
    abort "To run specs, install benchmark_unit gem"
  end
end

task 'spec:perf' => :check_benchmark_unit_gem