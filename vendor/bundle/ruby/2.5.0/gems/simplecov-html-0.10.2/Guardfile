# A sample Guardfile
# More info at https://github.com/guard/guard#readme

guard "bundler" do
  watch("Gemfile")
  # Uncomment next line if Gemfile contain `gemspec' command
  # watch(/^.+\.gemspec/)
end

guard "rake", :task => "assets:compile" do
  watch(%r{^assets\/})
end
