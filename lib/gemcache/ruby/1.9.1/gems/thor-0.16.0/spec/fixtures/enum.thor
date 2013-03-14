class Enum < Thor::Group
  include Thor::Actions

  desc "snack"
  class_option "fruit", :aliases => "-f", :type => :string, :enum => %w(apple banana)
  def snack
    puts options['fruit']
  end

end
