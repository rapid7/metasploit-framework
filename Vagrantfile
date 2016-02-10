# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure(2) do |config|
  config.vm.box = "bento/ubuntu-14.04"
  config.vm.provision :chef_apply do |chef|
    chef.version = "latest"
    chef.install = "force"
    chef.recipe = IO.read("provision.rb")
  end
end
