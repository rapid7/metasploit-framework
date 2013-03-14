# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = "daemons"
  s.version = "1.1.8"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.authors = ["Thomas Uehlinger"]
  s.date = "2012-02-06"
  s.description = "Daemons provides an easy way to wrap existing ruby scripts (for example a self-written server)  to be run as a daemon and to be controlled by simple start/stop/restart commands.  You can also call blocks as daemons and control them from the parent or just daemonize the current process.  Besides this basic functionality, daemons offers many advanced features like exception  backtracing and logging (in case your ruby script crashes) and monitoring and automatic restarting of your processes if they crash."
  s.email = "th.uehlinger@gmx.ch"
  s.extra_rdoc_files = ["README", "Releases", "TODO"]
  s.files = ["README", "Releases", "TODO"]
  s.homepage = "http://daemons.rubyforge.org"
  s.require_paths = ["lib"]
  s.rubyforge_project = "daemons"
  s.rubygems_version = "1.8.21"
  s.summary = "A toolkit to create and control daemons in different ways"

  if s.respond_to? :specification_version then
    s.specification_version = 2

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
    else
    end
  else
  end
end
