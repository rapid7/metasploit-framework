module Msf
###
#
# This module provides methods for WMAP-enabled modules
#
###

module Auxiliary::WMAPModule

	#
	# Initializes an instance of a WMAP module
	#
	def initialize(info = {})
		super
	end

	def wmap_enabled
		#enabled by default
		true
	end

	def wmap_type
		#default type
		nil
	end

	def wmap_target_host
		datastore['RHOST']
	end
	
	def wmap_target_port
		datastore['RPORT']
	end

	def wmap_target_ssl
		datastore['SSL']
	end
	
	def wmap_base_url
		res = (ssl ? "https://" : "http://")
		if datastore['VHOST'].nil?
			res << wmap_target_host
		else
			res << datastore['VHOST']
		end
		res << ":" + wmap_target_port
		res
	end


	#
	# WMAP Reporting methods	
	# Returns the base report id for a host,port,ssl
	#
	def wmap_base_report_id(host,port,ssl)
		if framework.db.report_active?
			if not ssl
				num_ssl = 0
			else
				num_ssl = 1
			end
		
			return	framework.db.last_report_id(host,port,num_ssl)
		end
		
		nil	
	end
	
	#
	# This method is used to add a new entry to the report table
	# It return the id to be used to add context to additional data
	#
	def wmap_report(parent_id,entity,etype,value,notes)
		if parent_id and framework.db.report_active? 
			return framework.db.create_report(parent_id,entity,etype,value,notes,self.name)
		end
		
		nil
	end
	
	#
	# This method identifies if we are connecetd to database
	#
	def report_active?
		framework.db.report_active?
	end
	
	#
	# This method allows wmap modules to access  
	# reports table.  Not tied to a specific report to be able to use data from other targets.
	#
	def wmap_report_sql(condition)
			return framework.db.report_sql(condition)
	end
	
	#
	# This method allows wmap modules to access  
	# requests table. The extra condition requires to start with a logical
	# operator like AND, OR. Not tied to a specific host,port to be able to use data from other targets. 
	#
	def wmap_request_sql(host,port,extra_condition)
			return framework.db.request_sql(host,port,extra_condition)
	end
	
	#
	# Modified from CGI.rb as we dont use arrays
	#
	def headersparse(qheaders)
		params = Hash.new()

 		qheaders.split(/[&;]/n).each do |pairs|
 			key, value = pairs.split(':',2)
 			if params.has_key?(key)
				#Error
 			else
				params[key] = value
 			end
 		end
		params
	end

	#modified from CGI.rb as we dont use arrays
	def queryparse(query)
		params = Hash.new()

 		query.split(/[&;]/n).each do |pairs|
 			key, value = pairs.split('=',2)
 			if params.has_key?(key)
				#Error
 			else
				params[key] = value
 			end
 		end
		params
	end

   	# Levenshtein distance algorithm  (slow, huge mem consuption)
   	def distance(a, b)
   		case
   		when a.empty?
			b.length
   		when b.empty?
			a.length
   		else
			[(a[0] == b[0] ? 0 : 1) + distance(a[1..-1], b[1..-1]),
			1 + distance(a[1..-1], b),
			2 + distance(a, b[1..-1])].min
   		end
   	end
				
end

###
#
# This module provides methods for WMAP File Scanner modules
#
###

module Auxiliary::WMAPScanFile
	include Auxiliary::WMAPModule

	def wmap_type
		:WMAP_FILE
	end 
end

###
#
# This module provides methods for WMAP Directory Scanner modules
#
###

module Auxiliary::WMAPScanDir
	include Auxiliary::WMAPModule

	def wmap_type
		:WMAP_DIR
	end 
end

###
#
# This module provides methods for WMAP Web Server Scanner modules
#
###

module Auxiliary::WMAPScanServer
	include Auxiliary::WMAPModule

	def wmap_type
		:WMAP_SERVER
	end 
end

###
#
# This module provides methods for WMAP Query Scanner modules
#
###

module Auxiliary::WMAPScanQuery
	include Auxiliary::WMAPModule

	def wmap_type
		:WMAP_QUERY
	end 
end

###
#
# This module provides methods for WMAP Unique Query Scanner modules
#
###

module Auxiliary::WMAPScanUniqueQuery
	include Auxiliary::WMAPModule

	def wmap_type
		:WMAP_UNIQUE_QUERY
	end 
	
	def signature(path,query)
		hsig = Hash.new()
		
		hsig = queryparse(query)
		
		#
		# Signature of the form ',p1,p2,pn' then to be appended to path: path,p1,p2,pn
		#
		
		sig = path
		hsig.each_pair do |par, val|
			sig << ","
			sig << par
		end
		sig
	end
end

###
#
# This module provides methods for WMAP Body Scanner modules
#
###

module Auxiliary::WMAPScanBody
	include Auxiliary::WMAPModule

	def wmap_type
		:WMAP_BODY
	end 
end

###
#
# This module provides methods for WMAP Headers Scanner modules
#
###

module Auxiliary::WMAPScanHeaders
	include Auxiliary::WMAPModule

	def wmap_type
		:WMAP_HEADERS
	end 
end

###
#
# This module provides methods for WMAP Generic Scanner modules
#
###

module Auxiliary::WMAPScanGeneric
	include Auxiliary::WMAPModule

	def wmap_type
		:WMAP_GENERIC
	end 
end

###
#
# This module provides methods for WMAP Crawler modules
#
###

module Auxiliary::WMAPCrawler
	include Auxiliary::WMAPModule

	def wmap_type
		:WMAP_CRAWLER
	end 
end

end
