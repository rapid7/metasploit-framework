# encoding: utf-8
$LOAD_PATH.unshift File.expand_path('../lib', __FILE__)

begin
  require 'bundler'
  Bundler::GemHelper.install_tasks
rescue LoadError => e
  $stderr.puts e
end

desc "run specs"
task(:spec) { ruby '-S rspec spec' }

desc "generate gemspec"
task 'rack-protection.gemspec' do
  require 'rack/protection/version'
  content = File.binread 'rack-protection.gemspec'

  # fetch data
  fields = {
    :authors => `git shortlog -sn`.force_encoding('utf-8').scan(/[^\d\s].*/),
    :email   => `git shortlog -sne`.force_encoding('utf-8').scan(/[^<]+@[^>]+/),
    :files   => `git ls-files`.force_encoding('utf-8').split("\n").reject { |f| f =~ /^(\.|Gemfile)/ }
  }

  # double email :(
  fields[:email].delete("konstantin.haase@gmail.com")

  # insert data
  fields.each do |field, values|
    updated = "  s.#{field} = ["
    updated << values.map { |v| "\n    %p" % v }.join(',')
    updated << "\n  ]"
    content.sub!(/  s\.#{field} = \[\n(    .*\n)*  \]/, updated)
  end

  # set version
  content.sub! /(s\.version.*=\s+).*/, "\\1\"#{Rack::Protection::VERSION}\""

  # escape unicode
  content.gsub!(/./) { |c| c.bytesize > 1 ? "\\u{#{c.codepoints.first.to_s(16)}}" : c }

  File.open('rack-protection.gemspec', 'w') { |f| f << content }
end

task :gemspec => 'rack-protection.gemspec'
task :default => :spec
task :test    => :spec
