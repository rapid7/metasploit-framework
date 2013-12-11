shared_context 'database connection' do
  #
  # Methods
  #

  # Temporarily removes the connection established by before(:suite) and restores it at the end of the block.
  def without_established_connection
    removed_connection = ActiveRecord::Base.remove_connection

    begin
      yield
    ensure
      if removed_connection
        ActiveRecord::Base.establish_connection(removed_connection)
      end
    end
  end
end