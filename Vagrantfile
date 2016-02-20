# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure(2) do |config|
  config.vm.box = "phusion/ubuntu-14.04-amd64"
  config.vm.network :forwarded_port, guest: 4444, host: 4444
  config.vm.provision :chef_apply do |chef|
    chef.version = "latest"
    chef.install = "force"
    chef.recipe = IO.read("scripts/shell/provision.rb")
  end
end
