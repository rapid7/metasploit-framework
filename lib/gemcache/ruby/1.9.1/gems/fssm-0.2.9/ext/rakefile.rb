# -*- encoding: utf-8 -*-
$LOAD_PATH.unshift(File.expand_path('../lib', File.dirname(__FILE__)))

require 'rubygems/dependency_installer'
require 'fssm'

# semi-elegant solution or hack? *shrug*
task :default do
  name, version = FSSM::Support.optimal_backend_dependency
  if name and version
    installer = Gem::DependencyInstaller.new({:domain => :both, :env_shebang => true})
    installer.install name, version
  end
end
