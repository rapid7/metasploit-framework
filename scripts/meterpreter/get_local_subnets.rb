
## Meterpreter script that display local subnets
## Provided by Nicob <nicob [at] nicob.net>
## Ripped from http://blog.metasploit.com/2006/10/meterpreter-scripts-and-msrt.html

client.net.config.each_route { |route|
    # Remove multicast and loopback interfaces
    next if route.subnet =~ /^(224\.|127\.)/
    next if route.subnet == '0.0.0.0'
    next if route.netmask == '255.255.255.255'
    print_line("Local subnet: #{route.subnet}/#{route.netmask}")
}
