# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure(2) do |config|
  config.ssh.forward_x11 = true
  config.vm.box = "ubuntu/xenial64"
  config.vm.network :forwarded_port, guest: 4444, host: 4444
  config.vm.provider "vmware" do |v|
	  v.memory = 2048
	  v.cpus = 2
  end
  config.vm.provider "virtualbox" do |v|
	  v.memory = 2048
	  v.cpus = 2
  end
  %w(.vimrc .gitconfig).each do |f|
    local = File.expand_path "~/#{f}"
    if File.exist? local
      config.vm.provision "file", source: local, destination: f
    end
  end

  [ #"echo 127.0.1.1 `cat /etc/hostname` >> /etc/hosts", work around a bug in official Ubuntu Xenial cloud images
    "apt-get update",
    "apt-get dist-upgrade -y",
    "apt-get -y install curl build-essential git tig vim john nmap libpq-dev libpcap-dev gnupg2 fortune postgresql postgresql-contrib",
  ].each do |step|
    config.vm.provision "shell", inline: step
  end

  [ "gpg --keyserver hkp://keys.gnupg.net --recv-keys 409B6B1796C275462A1703113804BB82D39DC0E3",
    "curl -L https://get.rvm.io | bash -s stable",
    "source ~/.rvm/scripts/rvm && cd /vagrant && rvm install `cat .ruby-version`",
    "source ~/.rvm/scripts/rvm && cd /vagrant && gem install bundler",
    "source ~/.rvm/scripts/rvm && cd /vagrant && bundle",
    "mkdir -p ~/.msf4",
  ].each do |step|
    config.vm.provision "shell", privileged: false, inline: step
  end
  config.vm.provision "file", source: "config/database.yml.vagrant", destination: "~/.msf4/database.yml"

  config.vm.provision "shell", inline: "sudo -u postgres psql postgres -tAc \"SELECT 1 FROM pg_roles WHERE rolname='vagrant'\" | grep -q 1 || sudo -u postgres createuser -s -e -w vagrant && sudo -u postgres psql -c \"ALTER USER vagrant with ENCRYPTED PASSWORD 'vagrant';\""

  ["msf_dev_db", "msf_test_db"].each do |database|
    config.vm.provision "shell", inline: "sudo -u postgres psql -lqt | awk '{ print $1 }' | grep -w #{database} | wc -l | grep -q 1 || sudo -u postgres createdb --owner vagrant #{database}"
  end
end
