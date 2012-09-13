
require 'spec/rake/spectask'
  
desc "Run all specifications"
Spec::Rake::SpecTask.new(:spec) do |t|
  t.libs << "lib"
  t.spec_opts = ["--color", "--require", "spec/spec_helper.rb"]
end
  
namespace :spec do

  desc "Run all specifications verbosely"
  Spec::Rake::SpecTask.new(:verbose) do |t|
    t.libs << "lib"
    t.spec_opts = ["--color", "--format", "specdoc", "--require", "spec/spec_helper.rb"]
  end
  
  desc "Run specific specification verbosely (specify SPEC)"
  Spec::Rake::SpecTask.new(:select) do |t|
    t.libs << "lib"
    t.spec_files = [ENV["SPEC"]]
    t.spec_opts = ["--color", "--format", "specdoc", "--require", "spec/spec_helper.rb"]
  end
  
end