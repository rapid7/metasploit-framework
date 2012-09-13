# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = %q{user-agent}
  s.version = "1.0.0"

  s.required_rubygems_version = Gem::Requirement.new(">= 1.2") if s.respond_to? :required_rubygems_version=
  s.authors = ["TJ Holowaychuk"]
  s.date = %q{2009-10-08}
  s.description = %q{User agent parser}
  s.email = %q{tj@vision-media.ca}
  s.extra_rdoc_files = ["README.rdoc", "lib/user-agent.rb", "lib/user-agent/agent.rb", "lib/user-agent/version.rb", "tasks/docs.rake", "tasks/gemspec.rake", "tasks/spec.rake"]
  s.files = ["History.rdoc", "Manifest", "README.rdoc", "Rakefile", "lib/user-agent.rb", "lib/user-agent/agent.rb", "lib/user-agent/version.rb", "spec/agent_spec.rb", "spec/agents_spec.rb", "spec/spec.opts", "spec/spec_helper.rb", "tasks/docs.rake", "tasks/gemspec.rake", "tasks/spec.rake", "user-agent.gemspec"]
  s.homepage = %q{}
  s.rdoc_options = ["--line-numbers", "--inline-source", "--title", "User-agent", "--main", "README.rdoc"]
  s.require_paths = ["lib"]
  s.rubyforge_project = %q{user-agent}
  s.rubygems_version = %q{1.3.5}
  s.summary = %q{User agent parser}

  if s.respond_to? :specification_version then
    current_version = Gem::Specification::CURRENT_SPECIFICATION_VERSION
    s.specification_version = 3

    if Gem::Version.new(Gem::RubyGemsVersion) >= Gem::Version.new('1.2.0') then
    else
    end
  else
  end
end
