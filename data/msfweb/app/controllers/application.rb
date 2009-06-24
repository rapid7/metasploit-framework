# Author: HDM <hdm@metasploit.com> and LMH <lmh@info-pull.com>
# Description: Helper methods for the controllers, including search and other
# functionality.

# Filters added to this controller will be run for all controllers in the application.
# Likewise, all the methods added will be available for all controllers.
class ApplicationController < ActionController::Base

  # Search functionality for modules
  def search_modules(mlist, terms)
    res = {}
    
    unless terms
      return nil
    end
    
    terms.strip! 
    
    # Match search terms
    mlist.each do |m|
	  
      if (terms.length == 0)
        res[m.refname]=m
        next
      end
	
      terms.split(/,/).each do |term|
			
		# handle a search string, search deep
		if(
			m.name.downcase.index(term) or
			m.description.downcase.index(term) or
			m.refname.downcase.index(term) or
			m.references.to_s.downcase.index(term) or
			m.author.to_s.downcase.index(term)
		)
          res[m.refname]=m
          break
        end
        
      end 
    end
	
    # Sort the modules by name
    list = []
    res.keys.sort{|a,b| res[a].name <=> res[b].name }.each do |n|
      list << res[n]
    end
      
    list
  end
  
  # Returns the module by id of specified type.
  def get_view_for_module(module_type, module_refname)
    @tmod = nil
    
    # Get available moduls of specified type
    case module_type
      when "exploit"
        @mod_list = Exploit.find_all()
      when "auxiliary"
        @mod_list = Auxiliary.find_all()
      when "payload"
        @mod_list = Payload.find_all()
      when "nop"
        @mod_list = Nop.find_all()
      when "encoder"
        @mod_list = Encoder.find_all()
      else
        return @tmod
    end
    
    # Return the module if found
	if module_refname
		@mod_list.each do |m|
			if m.refname.gsub('/', ':') == module_refname
				@tmod = m
				break
			end
		end
	end
	
	return @tmod
  end

end
