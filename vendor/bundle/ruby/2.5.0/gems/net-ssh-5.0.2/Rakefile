
#
# Also in your terminal environment run:
#   $ export LANG=en_US.UTF-8
#   $ export LANGUAGE=en_US.UTF-8
#   $ export LC_ALL=en_US.UTF-8

require "rubygems"
require "rake"
require "rake/clean"
require "bundler/gem_tasks"

require "rdoc/task"

desc "When releasing make sure NET_SSH_BUILDGEM_SIGNED is set"
task :check_NET_SSH_BUILDGEM_SIGNED do
  raise "NET_SSH_BUILDGEM_SIGNED should be set to release" unless ENV['NET_SSH_BUILDGEM_SIGNED']
end

Rake::Task[:release].enhance [:check_NET_SSH_BUILDGEM_SIGNED]
Rake::Task[:release].prerequisites.unshift(:check_NET_SSH_BUILDGEM_SIGNED)

task default: ["build"]
CLEAN.include ['pkg', 'rdoc']
name = "net-ssh"

require_relative "lib/net/ssh/version"
version = Net::SSH::Version::CURRENT

extra_files = %w[LICENSE.txt THANKS.txt CHANGES.txt]
RDoc::Task.new do |rdoc|
  rdoc.rdoc_dir = "rdoc"
  rdoc.title = "#{name} #{version}"
  rdoc.generator = 'hanna' # gem install hanna-nouveau
  rdoc.main = 'README.rdoc'
  rdoc.rdoc_files.include("README*")
  rdoc.rdoc_files.include("bin/*.rb")
  rdoc.rdoc_files.include("lib/**/*.rb")
  extra_files.each { |file|
    rdoc.rdoc_files.include(file) if File.exist?(file)
  }
end

namespace :cert do
  desc "Update public cert from private - only run if public is expired"
  task :update_public_when_expired do
    require 'openssl'
    require 'time'
    raw = File.read "net-ssh-public_cert.pem"
    certificate = OpenSSL::X509::Certificate.new raw
    raise Exception, "Not yet expired: #{certificate.not_after}" unless certificate.not_after < Time.now
    sh "gem cert --build netssh@solutious.com --days 365*5 --private-key /mnt/gem/net-ssh-private_key.pem"
    sh "mv gem-public_cert.pem net-ssh-public_cert.pem"
    sh "gem cert --add net-ssh-public_cert.pem"
  end
end

namespace :rdoc do
  desc "Update gh-pages branch"
  task :publish do
    # copy/checkout
    rm_rf "/tmp/net-ssh-rdoc"
    rm_rf "/tmp/net-ssh-gh-pages"
    cp_r "./rdoc", "/tmp/net-ssh-rdoc"
    mkdir "/tmp/net-ssh-gh-pages"
    Dir.chdir "/tmp/net-ssh-gh-pages" do
      sh "git clone --branch gh-pages --single-branch https://github.com/net-ssh/net-ssh"
      rm_rf "/tmp/net-ssh-gh-pages/net-ssh/*"
    end
    # update
    sh "cp -rf ./rdoc/* /tmp/net-ssh-gh-pages/net-ssh/"
    Dir.chdir "/tmp/net-ssh-gh-pages/net-ssh" do
      sh "git add -A ."
      sh "git commit -m \"Update docs\""
    end
    # publish
    Dir.chdir "/tmp/net-ssh-gh-pages/net-ssh" do
      sh "git push origin gh-pages"
    end
  end
end

require 'rake/testtask'

Rake::TestTask.new do |t|
  t.libs = ["lib", "test"]
  t.libs << "test/integration" if ENV['NET_SSH_RUN_INTEGRATION_TESTS']
  t.libs << "test/win_integration" if ENV['NET_SSH_RUN_WIN_INTEGRATION_TESTS']
  test_files = FileList['test/**/test_*.rb']
  test_files -= FileList['test/integration/**/test_*.rb'] unless ENV['NET_SSH_RUN_INTEGRATION_TESTS']
  test_files -= FileList['test/win_integration/**/test_*.rb'] unless ENV['NET_SSH_RUN_WIN_INTEGRATION_TESTS']
  test_files -= FileList['test/manual/test_*.rb']
  test_files -= FileList['test/test_pageant.rb']
  test_files -= FileList['test/test/**/test_*.rb']
  t.test_files = test_files
end

desc "Run tests of Net::SSH:Test"
Rake::TestTask.new do |t|
  t.name = "test_test"
  # we need to run test/test separatedly as it hacks io + other modules
  t.libs = ["lib", "test"]
  test_files = FileList['test/test/**/test_*.rb']
  t.test_files = test_files
end
