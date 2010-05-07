module Msf
module Scripts
module Meterpreter
module Common

#
# Commonly used methods and techniques for Meterpreter scripts
#

#
# These methods should only print output in the case of an error. All code should be tab indented
# All methods should follow the naming coventions below (separate words with "_", end queries with a ?, etc)
#
#List all Windows Services present. Returns an Array containing the names of the services.
def service_list
	serviceskey = "HKLM\\SYSTEM\\CurrentControlSet\\Services"
	threadnum = 0
	a =[]
	services = []
	registry_enumkeys(serviceskey).each do |s|
		if threadnum < 10
			a.push(::Thread.new {
					begin
						srvtype = registry_getvaldata("#{serviceskey}\\#{s}","Type").to_s
						if srvtype =~ /32|16/
							services << s
						end
					rescue
					end
				})
			threadnum += 1
		else
			sleep(0.05) and a.delete_if {|x| not x.alive?} while not a.empty?
			threadnum = 0
		end
	end

	return services
end
#Get Windows Service information. Information returned in a hash with display name, startup
#mode and command executed by the service. Service name is case sensitive. Hash keys are Name,
#Start, Command and Credentials.
def service_info(name)
	service = {}
	servicekey = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\#{name.chomp}"
	service["Name"] = registry_getvaldata(servicekey,"DisplayName").to_s
	srvstart = registry_getvaldata(servicekey,"Start").to_i
	if srvstart == 2
		service["Startup"] = "Auto"
	elsif srvstart == 3
		service["Startup"] = "Manual"
	elsif srvstart == 4
		service["Startup"] = "Disabled"
	end
	service["Command"] = registry_getvaldata(servicekey,"ImagePath").to_s
	service["Creentials"] = registry_getvaldata(servicekey,"ObjectName").to_s
	return service
end
#Changes a given service startup mode, name must be provided and the mode. Mode is a string with either
#auto, manual or disable for the corresponding setting. The name of the service is case sensitive.
def service_change_startup(name,mode)
	servicekey = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\#{name.chomp}"
	case mode.downcase
	when "auto" then
		registry_setvaldata(servicekey,"Start","2","REG_DWORD")
	when "manual" then
		registry_setvaldata(servicekey,"Start","3","REG_DWORD")
	when "disable" then
		registry_setvaldata(servicekey,"Start","4","REG_DWORD")
	end
end


end
end
end
end

