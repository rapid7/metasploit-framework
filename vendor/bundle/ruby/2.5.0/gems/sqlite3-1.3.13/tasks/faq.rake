# Generate FAQ
desc "Generate the FAQ document"
task :faq => ['faq/faq.html']

file 'faq/faq.html' => ['faq/faq.rb', 'faq/faq.yml'] do
  cd 'faq' do
    ruby "faq.rb > faq.html"
  end
end
