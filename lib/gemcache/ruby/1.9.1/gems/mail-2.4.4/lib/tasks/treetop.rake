namespace :treetop do

  desc "Pre-generate all the .treetop files into .rb files"
  task :generate do
    Dir.glob(File.expand_path('../../mail/parsers/*.treetop', __FILE__)).each do |filename|
      `bundle exec tt #{filename}`
    end
  end

end
