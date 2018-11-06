# encoding: utf-8
require 'bundler/gem_tasks'

task :clean do
	system "rm *.gem &> /dev/null"
end


require 'github_changelog_generator/task'
GitHubChangelogGenerator::RakeTask.new :changelog do |config|
  token = ENV['CHANGELOG_GITHUB_TOKEN']
  if token.nil?
    warn "!!WARNING!! Missing Github Token Environment Variable. Fix before you run rake changelog. !!WARNING!!"
  end
end
