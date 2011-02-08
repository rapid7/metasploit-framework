
require 'rubygems'
require 'AWS'		## requires the amazon-ec2 gem

module Lab
module AmazonController

  	
  	@ec2 = AWS::EC2::Base.new(:access_key_id => ENV['ACCESS_KEY_ID'], :secret_access_key => ENV['SECRET_ACCESS_KEY'])

	def list_amazon
  		@ec2.describe_images(:owner_id => "amazon").imagesSet.item.each do |image|
			print_line "image: #{image}"
		end
	end

end
end

