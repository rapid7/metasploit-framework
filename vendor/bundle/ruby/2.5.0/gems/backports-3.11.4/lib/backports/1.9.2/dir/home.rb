unless Dir.respond_to? :home
  def Dir.home(user = "")
    File.expand_path "~#{user}"
  end
end
