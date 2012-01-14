require_relative "regf"
require_relative "nodekey"

module Rex
module Registry

class Hive
	attr_accessor :root_key, :hive_regf

	def initialize(hivepath)
		
		hive_blob = open(hivepath, "rb") { |io| io.read }	
		@hive_regf = RegfBlock.new(hive_blob)
	
		@root_key = NodeKey.new(hive_blob, 0x1000 + @hive_regf.root_key_offset)
	end

	def relative_query(path)

		if path == "" || path == "\\"
			return @root_key
		end

		current_child = nil
		paths = path.split("\\")

		@root_key.lf_record.children.each do |child|			
			next if child.name.downcase != paths[1].downcase

			current_child = child
		
			if paths.length == 2
				current_child.full_path = path
				return current_child
			end			
			
			2.upto(paths.length) do |i|

				if i == paths.length
					current_child.full_path = path
					return current_child
				else
					if current_child.lf_record
						current_child.lf_record.children.each do |c|
							next if c.name.downcase != paths[i].downcase
							
							current_child = c
							
							break
						end
					end
				end
		
			end
		end

		current_child.full_path = path
		return current_child
	end

	def value_query(path)
		if path == "" || path == "\\"
			return nil
		end
	
		paths = path.split("\\")

		@root_key.lf_record.children.each do |root_child|
			next if root_child.name.downcase != paths[1].downcase

			current_child = root_child

			if paths.length == 2
				return nil
			end

			2.upto(paths.length - 1) do |i|
			        next if !current_child.lf_record
	
		                current_child.lf_record.children.each do |c|
                                	next if c.name != paths[i]
                                        current_child = c
                                        
                                        break
                                end
                        end

			if !current_child.value_list || current_child.value_list.values.length == 0
				return nil
			end

			current_child.value_list.values.each do |value|
				next if value.name.downcase != paths[paths.length - 1].downcase
				
				value.full_path = path
				return value
			end
		end
	end

	def rip_boot_key
	
		return if @hive_regf.hive_name !~ /SYSTEM/
	
		scrambled_key = []
		default_control_set = ""
		
		@root_key.lf_record.children.each do |node|
			next if node.name != "Select"
		
			node.value_list.values.each do |value|
				next if value.name != "Default"
		
				default_control_set = "ControlSet00" + value.value.data.unpack('c').first.to_s
			end
		end

		puts "Default Control Set: " + default_control_set

		@root_key.lf_record.children.each do |node|
			next if node.name != default_control_set
			
			node.lf_record.children.each do |cchild|
				next if cchild.name != "Control"
				
				puts "Found: " + cchild.name

				cchild.lf_record.children.each do |lsachild|
					next if lsachild.name != "Lsa"

					puts "Found: " + lsachild.name

					%w[JD Skew1 GBG Data].each do |key|
						lsachild.lf_record.children.each do |child|
							next if child.name != key
	
							puts "Found: " + child.name
		
							child.class_name_data.each_byte do |byte|
								scrambled_key << byte if byte != 0x00 
							end
						end
					end
				end

			end
		end

		scrambler = [ 0x8, 0x5, 0x4, 0x2, 0xb, 0x9, 0xd, 0x3, 0x0, 0x6, 0x1, 0xc, 0xe, 0xa, 0xf, 0x7 ]
		bootkey = scrambled_key	

		0.upto(0x10-1) do |i|
			#p scrambler[i]
			bootkey[i] = scrambled_key[scrambler[i]]
		end
		
		puts "Bootkey: " + bootkey.to_s
	end
end

end
end
