
namespace :docs do
  
  desc 'Remove rdoc products'
  task :remove => [:clobber_docs]
  
  desc 'Build docs, and open in browser for viewing (specify BROWSER)'
  task :open do
    browser = ENV["BROWSER"] || "safari"
    sh "open -a #{browser} doc/index.html"
  end
  
end