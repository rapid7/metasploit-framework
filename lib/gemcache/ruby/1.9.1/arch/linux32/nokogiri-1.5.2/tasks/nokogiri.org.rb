#
#  note that this file will only work if you've got the `nokogiri.org`
#  repo checked out, and you've got an rvm gemset "1.8.7@nokogiri"
#  bundled with both nokogiri's and nokogiri.org's gems.
#
namespace :docs do
  desc "generate HTML docs for nokogiri.org"
  task :website do
    system 'rvm use 1.8.7@nokogiri' # see above
    title = "#{HOE.name}-#{HOE.version} Documentation"

    options = []
    options << "--main=#{HOE.readme_file}"
    options << '--format=activerecord'
    options << '--threads=1'
    options << "--title=#{title.inspect}"

    options += HOE.spec.require_paths
    options += HOE.spec.extra_rdoc_files
    require 'rdoc/rdoc'
    ENV['RAILS_ROOT'] ||= File.expand_path(File.join('..', 'nokogiri_ws'))
    RDoc::RDoc.new.document options
  end
end
