# -*- mode: ruby -*-
# vi: set ft=ruby :

display_name = "metasploit-framework"

Vagrant.configure(2) do |config|
  config.ssh.forward_x11 = true
  config.vm.box = "hashicorp/bionic64" # https://app.vagrantup.com/hashicorp/boxes/bionic64
  config.vm.network :forwarded_port, guest: 4444, host: 4444
  config.vm.provider "vmware_desktop" do |v|
	  v.memory = 2048
	  v.cpus = 2
    v.vmx['displayname'] = display_name
    #v.gui = true # uncomment to show VM in your hypervisor's GUI
  end
  config.vm.provider "virtualbox" do |v|
    v.name = display_name
	  v.memory = 2048
	  v.cpus = 2
    #v.gui = true # uncomment to show VM in your hypervisor's GUI
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

  [ # use the rvm install method used in omnibus install
    # only show stderr when gpg really fails. avoids superfluous stderr from gpg
    'out=`curl -sSL https://rvm.io/mpapis.asc | gpg --import - 2>&1` && echo "imported mpapis.asc" || echo $out 1>&2',
    'out=`curl -sSL https://rvm.io/pkuczynski.asc | gpg --import - 2>&1` && echo "imported pkuczynski.asc" || echo $out 1>&2',
    'out=`curl -L -sSL https://get.rvm.io | bash -s stable 2>&1` && echo "rvm installed" || echo $out 1>&2',
    # only install Ruby if the right version isn't already present
    "echo 'Installing Ruby if necessary'",
    'cd /vagrant && rv=`cat .ruby-version` && source ~/.rvm/scripts/rvm && rvm list strings | grep -q $rv || rvm install $rv',
    'source ~/.rvm/scripts/rvm && cd /vagrant && gem install --quiet bundler && bundle',
    'mkdir -p ~/.msf4',
  ].each do |step|
    config.vm.provision "shell", privileged: false, inline: step
  end
  config.vm.provision "file", source: "config/database.yml.vagrant", destination: "~/.msf4/database.yml"

  config.vm.provision "shell", inline: "sudo -u postgres psql postgres -tAc \"SELECT 1 FROM pg_roles WHERE rolname='vagrant'\" | grep -q 1 || sudo -u postgres createuser -s -e -w vagrant && sudo -u postgres psql -c \"ALTER USER vagrant with ENCRYPTED PASSWORD 'vagrant';\""

  ["msf_dev_db", "msf_test_db"].each do |database|
    config.vm.provision "shell", inline: "sudo -u postgres psql -lqt | awk '{ print $1 }' | grep -w #{database} | wc -l | grep -q 1 || sudo -u postgres createdb --owner vagrant #{database}"
  end
end
