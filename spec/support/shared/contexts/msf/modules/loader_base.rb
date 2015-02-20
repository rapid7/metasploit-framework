# -*- coding:binary -*-
shared_context "Msf::Modules::Loader::Base" do
  let(:parent_path) do
    parent_pathname.to_s
  end

  let(:parent_pathname) do
    root_pathname.join('modules')
  end

  let(:root_pathname) do
    Pathname.new(Msf::Config.install_root)
  end
end
