require 'rake/clean'
require 'rake/testtask'
require 'fileutils'
require 'date'

# CI Reporter is only needed for the CI
begin
  require 'ci/reporter/rake/test_unit'
rescue LoadError
end

task :default => :test
task :spec => :test

CLEAN.include "**/*.rbc"

def source_version
  @source_version ||= begin
    load './lib/sinatra/version.rb'
    Sinatra::VERSION
  end
end

def prev_feature
  source_version.gsub(/^(\d\.)(\d+)\..*$/) { $1 + ($2.to_i - 1).to_s }
end

def prev_version
  return prev_feature + '.0' if source_version.end_with? '.0'
  source_version.gsub(/\d+$/) { |s| s.to_i - 1 }
end

# SPECS ===============================================================

task :test do
  ENV['LANG'] = 'C'
  ENV.delete 'LC_CTYPE'
end

Rake::TestTask.new(:test) do |t|
  t.test_files = FileList['test/*_test.rb']
  t.ruby_opts = ['-rubygems'] if defined? Gem
  t.ruby_opts << '-I.'
  t.warning = true
end

Rake::TestTask.new(:"test:core") do |t|
  core_tests = %w[base delegator encoding extensions filter
     helpers mapped_error middleware radius rdoc
     readme request response result route_added_hook
     routing server settings sinatra static templates]
  t.test_files = core_tests.map {|n| "test/#{n}_test.rb"}
  t.ruby_opts = ["-rubygems"] if defined? Gem
  t.ruby_opts << "-I."
  t.warning = true
end

# Rcov ================================================================

namespace :test do
  desc 'Measures test coverage'
  task :coverage do
    rm_f "coverage"
    sh "rcov -Ilib test/*_test.rb"
  end
end

# Website =============================================================

desc 'Generate RDoc under doc/api'
task 'doc'     => ['doc:api']
task('doc:api') { sh "yardoc -o doc/api" }
CLEAN.include 'doc/api'

# README ===============================================================

task :add_template, [:name] do |t, args|
  Dir.glob('README.*') do |file|
    code = File.read(file)
    if code =~ /^===.*#{args.name.capitalize}/
      puts "Already covered in #{file}"
    else
      template = code[/===[^\n]*Liquid.*index\.liquid<\/tt>[^\n]*/m]
      if !template
        puts "Liquid not found in #{file}"
      else
        puts "Adding section to #{file}"
        template = template.gsub(/Liquid/, args.name.capitalize).gsub(/liquid/, args.name.downcase)
        code.gsub! /^(\s*===.*CoffeeScript)/, "\n" << template << "\n\\1"
        File.open(file, "w") { |f| f << code }
      end
    end
  end
end

# Thanks in announcement ===============================================

team = ["Ryan Tomayko", "Blake Mizerany", "Simon Rozet", "Konstantin Haase"]
desc "list of contributors"
task :thanks, [:release,:backports] do |t, a|
  a.with_defaults :release => "#{prev_version}..HEAD",
    :backports => "#{prev_feature}.0..#{prev_feature}.x"
  included = `git log --format=format:"%aN\t%s" #{a.release}`.lines.map { |l| l.force_encoding('binary') }
  excluded = `git log --format=format:"%aN\t%s" #{a.backports}`.lines.map { |l| l.force_encoding('binary') }
  commits  = (included - excluded).group_by { |c| c[/^[^\t]+/] }
  authors  = commits.keys.sort_by { |n| - commits[n].size } - team
  puts authors[0..-2].join(', ') << " and " << authors.last,
    "(based on commits included in #{a.release}, but not in #{a.backports})"
end

desc "list of authors"
task :authors, [:commit_range, :format, :sep] do |t, a|
  a.with_defaults :format => "%s (%d)", :sep => ", ", :commit_range => '--all'
  authors = Hash.new(0)
  blake   = "Blake Mizerany"
  overall = 0
  mapping = {
    "blake.mizerany@gmail.com" => blake, "bmizerany" => blake,
    "a_user@mac.com" => blake, "ichverstehe" => "Harry Vangberg",
    "Wu Jiang (nouse)" => "Wu Jiang" }
  `git shortlog -s #{a.commit_range}`.lines.map do |line|
    line = line.force_encoding 'binary' if line.respond_to? :force_encoding
    num, name = line.split("\t", 2).map(&:strip)
    authors[mapping[name] || name] += num.to_i
    overall += num.to_i
  end
  puts "#{overall} commits by #{authors.count} authors:"
  puts authors.sort_by { |n,c| -c }.map { |e| a.format % e }.join(a.sep)
end

desc "generates TOC"
task :toc, [:readme] do |t, a|
  a.with_defaults :readme => 'README.md'

  def self.link(title)
    title.downcase.gsub(/(?!-)\W /, '-').gsub(' ', '-').gsub(/(?!-)\W/, '')
  end

  puts "* [Sinatra](#sinatra)"
  title = Regexp.new('(?<=\* )(.*)') # so Ruby 1.8 doesn't complain
  File.binread(a.readme).scan(/^##.*/) do |line|
    puts line.gsub(/#(?=#)/, '    ').gsub('#', '*').gsub(title) { "[#{$1}](##{link($1)})" }
  end
end

# PACKAGING ============================================================

if defined?(Gem)
  # Load the gemspec using the same limitations as github
  def spec
    require 'rubygems' unless defined? Gem::Specification
    @spec ||= eval(File.read('sinatra.gemspec'))
  end

  def package(ext='')
    "pkg/sinatra-#{spec.version}" + ext
  end

  desc 'Build packages'
  task :package => %w[.gem .tar.gz].map {|e| package(e)}

  desc 'Build and install as local gem'
  task :install => package('.gem') do
    sh "gem install #{package('.gem')}"
  end

  directory 'pkg/'
  CLOBBER.include('pkg')

  file package('.gem') => %w[pkg/ sinatra.gemspec] + spec.files do |f|
    sh "gem build sinatra.gemspec"
    mv File.basename(f.name), f.name
  end

  file package('.tar.gz') => %w[pkg/] + spec.files do |f|
    sh <<-SH
      git archive \
        --prefix=sinatra-#{source_version}/ \
        --format=tar \
        HEAD | gzip > #{f.name}
    SH
  end

  task 'release' => ['test', package('.gem')] do
    if File.binread("CHANGELOG.md") =~ /= \d\.\d\.\d . not yet released$/i
      fail 'please update the changelog first' unless %x{git symbolic-ref HEAD} == "refs/heads/prerelease\n"
    end

    sh <<-SH
      gem install #{package('.gem')} --local &&
      gem push #{package('.gem')}  &&
      git commit --allow-empty -a -m '#{source_version} release'  &&
      git tag -s v#{source_version} -m '#{source_version} release'  &&
      git tag -s #{source_version} -m '#{source_version} release'  &&
      git push && (git push sinatra || true) &&
      git push --tags && (git push sinatra --tags || true)
    SH
  end
end
