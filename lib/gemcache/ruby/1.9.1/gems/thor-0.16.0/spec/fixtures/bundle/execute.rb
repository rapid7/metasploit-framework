class Execute < Thor
  desc "ls", "Execute ls"
  def ls
    system "ls"
  end
end
