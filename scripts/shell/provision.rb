execute "apt-get update -y"
execute "apt-get upgrade -y"

package [
  "autoconf",
  "bison",
  "build-essential",
  "curl",
  "git-core",
  "libapr1",
  "libaprutil1",
  "libcurl4-openssl-dev",
  "libffi-dev",
  "libgmp3-dev",
  "libpcap-dev",
  "libpq-dev",
  "libreadline-dev",
  "libreadline6-dev",
  "libsqlite3-dev",
  "libssl-dev",
  "libsvn1",
  "libtool",
  "libxml2",
  "libxml2-dev",
  "libxslt-dev",
  "libxslt1-dev",
  "libyaml-dev",
  "locate",
  "ncurses-dev",
  "openssl",
  "postgresql",
  "postgresql-contrib",
  "python-software-properties",
  "sqlite3",
  "vim",
  "wget",
  "xsel",
  "zlib1g",
  "zlib1g-dev",
]

sql = "SELECT 1 FROM pg_roles WHERE rolname='vagrant'"
create_user = "createuser -s -e -w vagrant"
execute "psql postgres -tAc \"#{sql}\" | grep -q 1 || #{create_user}" do
  user "postgres"
end

sql = "SELECT 1 FROM pg_roles WHERE rolname='vagrant'"
execute "createdb" do
  user "vagrant"
  not_if { "psql postgres -tAc \"#{sql}\" | grep -q 1" }
end

file "/vagrant/.msf4/database.yml" do
  content <<-EOH
# Development Database
development: &pgsql
  adapter: postgresql
  database: msf_dev_db
  username: vagrant
  host: localhost
  port: 5432
  pool: 5
  timeout: 5

# Production database -- same as dev
production: &production
  <<: *pgsql

# Test database -- not the same, since it gets dropped all the time
test:
  <<: *pgsql
  database: msf_test_db
EOH
end

["postgresql"].each do |service_name|
  service service_name do
    action [:enable, :start]
  end
end

git "/usr/local/rbenv" do
  repository "https://github.com/sstephenson/rbenv.git"
end

file "/etc/profile.d/rbenv.sh" do
  content <<-CONTENT
export RBENV_ROOT="/usr/local/rbenv"
export PATH="/usr/local/rbenv/bin:$PATH"
eval "$(rbenv init -)"
  CONTENT
end

directory "/usr/local/rbenv/plugins"
git "/usr/local/rbenv/plugins/ruby-build" do
  repository "https://github.com/sstephenson/ruby-build.git"
end

ruby_version = `cat .ruby-version`.strip
bash "install_ruby" do
  user "root"
  not_if { ::Dir.exist?("/usr/local/rbenv/versions/#{ruby_version}") }
  code <<-EOH
source /etc/profile.d/rbenv.sh
rbenv install #{ruby_version}
rbenv global #{ruby_version}
  EOH
end

bash "install_bundler" do
  user "root"
  code <<-EOH
source /etc/profile.d/rbenv.sh
gem install bundler --no-ri --no-rdoc
  EOH
end
