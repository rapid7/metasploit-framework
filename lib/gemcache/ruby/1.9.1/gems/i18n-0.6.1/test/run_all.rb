def bundle_check
  `bundle check` == "The Gemfile's dependencies are satisfied\n"
end

command  = 'ruby -w -Ilib -Itest test/all.rb'
gemfiles = %w(ci/Gemfile.rails-3.x ci/Gemfile.rails-2.3.x ci/Gemfile.no-rails)

results = gemfiles.map do |gemfile|
  puts "BUNDLE_GEMFILE=#{gemfile}"
  ENV['BUNDLE_GEMFILE'] = gemfile

  unless bundle_check
    puts "bundle install"
    system('bundle install')
  end

  puts command
  system('ruby -w -Ilib -Itest test/all.rb')
end

exit(results.inject(true) { |a, b| a && b })
