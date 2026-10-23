require_relative '../../../lib/msfenv'
require 'msf/base'
require 'rspec'
require_relative '../../garak'

def garak_test_runner(klass)
  runner_class = klass.dup
  runner_class.framework = Msf::Simple::Framework.create('DisableDatabase' => true, 'DeferModuleLoads' => true)
  runner_class.refname = 'garak/test'
  runner_class.orig_cls = runner_class
  runner_class.new
end
