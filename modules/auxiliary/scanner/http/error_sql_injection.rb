##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'rex/proto/http'
require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::WmapScanUniqueQuery
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report


  def initialize(info = {})
    super(update_info(info,
      'Name'   		=> 'HTTP Error Based SQL Injection Scanner',
      'Description'	=> %q{
        This module identifies the existence of Error Based SQL injection issues. Still requires alot of work

      },
      'Author' 		=> [ 'et [at] cyberspace.org' ],
      'License'		=> BSD_LICENSE))

    register_options(
      [
        OptEnum.new('METHOD', [true, 'HTTP Request Method', 'GET', ['GET', 'POST']]),
        OptString.new('PATH', [ true,  "The path/file to test SQL injection", '/default.aspx']),
        OptString.new('QUERY',[ false,  "HTTP URI Query", '']),
        OptString.new('DATA', [ false,  "HTTP Body/Data Query", ''])
      ], self.class)

    register_advanced_options(
      [
        OptBool.new('NoDetailMessages', [ false, "Do not display detailed test messages", true ])
      ], self.class)

  end

  def run_host(ip)

    http_method = datastore['METHOD'].upcase

    qvars = nil

    sqlinj = [
      [ "'" ,'Single quote'],
      [ "')",'Single quote and parenthesis'],
      [ "\"",'Double quote'],
      [ "%u0027",'unicode single quote'],
      [ "%u02b9",'unicode single quote'],
      [ "%u02bc",'unicode single quote'],
      [ "%u02c8",'unicode single quote'],
      [ "%c0%27",'unicode single quote'],
      [ "%c0%a7",'unicode single quote'],
      [ "%e0%80%a7",'unicode single quote'],
      [ "#{rand(10)}'", 'Random value with single quote']
    ]

    errorstr = [
      ["Unclosed quotation mark after the character string",'MSSQL','string'],
      ["Syntax error in string in query expression",'MSSQL','string'],
      ["Microsoft OLE DB Provider",'MSSQL','unknown'],
      ["You have an error in your SQL syntax",'MySQL','unknown'],
      ["java.sql.SQLException",'unknown','unknown'],
      ["ORA-",'ORACLE','unknown'],
      ["PLS-",'ORACLE','unknown'],
      ["Syntax error",'unknown','unknown'],
    ]

    #
    # Dealing with empty query/data and making them hashes.
    #

    if  http_method =='GET'
      if not datastore['QUERY'].empty?
        qvars = queryparse(datastore['QUERY']) #Now its a Hash
      else
        return
      end
    else
      if not datastore['DATA'].empty?
        qvars = queryparse(datastore['DATA']) #Now its a Hash
      else
        return
      end
    end

    #
    # Send normal request to check if error is generated
    # (means the error is caused by other means)
    #
    #

    if http_method == 'POST'
      reqinfo = {
        'uri'  		=> normalize_uri(datastore['PATH']),
        'query' 	=> datastore['QUERY'],
        'data' 		=> datastore['DATA'],
        'method'   	=> http_method,
        'ctype'		=> 'application/x-www-form-urlencoded',
        'encode'	=> false
      }
    else
      reqinfo = {
        'uri'  		=> normalize_uri(datastore['PATH']),
        'query' 	=> datastore['QUERY'],
        'method'   	=> http_method,
        'ctype'		=> 'application/x-www-form-urlencoded',
        'encode'	=> false
      }
    end

    begin
      normalres = send_request_raw(reqinfo, 20)

    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
    rescue ::Timeout::Error, ::Errno::EPIPE
    end

    if !datastore['NoDetailMessages']
      print_status("Normal request sent.")
    end

    found = false
    inje = nil
    dbt = nil
    injt = nil

    if normalres
      errorstr.each do |estr,dbtype,injtype|
        if normalres.body.include? estr
          found = true
          inje = estr
          dbt = dbtype
          injt = injtype
        end
      end

      if found
        print_error("[#{wmap_target_host}] Error string appears in the normal response, unable to test")
        print_error("[#{wmap_target_host}] Error string: '#{inje}'")
        print_error("[#{wmap_target_host}] DB TYPE: #{dbt}, Error type '#{injt}'")

        report_web_vuln(
          :host	=> ip,
          :port	=> rport,
          :vhost  => vhost,
          :ssl    => ssl,
          :path	=> datastore['PATH'],
          :method => datastore['METHOD'],
          :pname  => "",
          :proof  => "Error: #{inje}",
          :risk   => 2,
          :confidence   => 50,
          :category     => 'Database error',
          :description  => "Error string appears in the normal response #{inje} #{dbt}",
          :name   => 'Database error'
        )

        return
      end
    else
      print_error("[#{wmap_target_host}] No response")
      return
    end

    #
    # Test URI Query parameters
    #

    found = false

    if qvars
      sqlinj.each do |istr,idesc|

        if found
          break
        end

        qvars.each do |key,value|
          if http_method == 'POST'
            qvars = queryparse(datastore['DATA']) #Now its a Hash
          else
            qvars = queryparse(datastore['QUERY']) #Now its a Hash
          end
          qvars[key] = qvars[key]+istr

          if !datastore['NoDetailMessages']
            print_status("- Testing query with #{idesc}. Parameter #{key}:")
          end

          fstr = ""
          qvars.each_pair do |var,val|
            fstr += var+"="+val+"&"
          end

          if http_method == 'POST'
            reqinfo = {
              'uri'  		=> normalize_uri(datastore['PATH']),
              'query'		=> datastore['QUERY'],
              'data' 		=> fstr,
              'method'   	=> http_method,
              'ctype'		=> 'application/x-www-form-urlencoded',
              'encode'	=> false
            }
          else
            reqinfo = {
              'uri'  		=> normalize_uri(datastore['PATH']),
              'query' 	=> fstr,
              'method'   	=> http_method,
              'ctype'		=> 'application/x-www-form-urlencoded',
              'encode'	=> false
            }
          end

          begin

            testres = send_request_raw(reqinfo, 20)

          rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
          rescue ::Timeout::Error, ::Errno::EPIPE
          end

          if testres
            errorstr.each do |estr,dbtype,injtype|
              if testres.body.include? estr
                found = true
                inje = estr
                dbt = dbtype
                injt = injtype
              end
            end

            if found
              print_good("[#{wmap_target_host}] SQL Injection found. (#{idesc}) (#{datastore['PATH']})")
              print_good("[#{wmap_target_host}] Error string: '#{inje}' Test Value: #{qvars[key]}")
              print_good("[#{wmap_target_host}] Vuln query parameter: #{key} DB TYPE: #{dbt}, Error type '#{injt}'")

              report_web_vuln(
                :host	=> ip,
                :port	=> rport,
                :vhost  => vhost,
                :ssl    => ssl,
                :path	=> datastore['PATH'],
                :method => datastore['METHOD'],
                :pname  => key,
                :proof  => istr,
                :risk   => 2,
                :confidence   => 50,
                :category     => 'SQL injection',
                :description  => "Error string appears in the normal response #{inje} #{dbt}",
                :name   => 'SQL injection'
              )

              return
            end
          else
            print_error("[#{wmap_target_host}] No response")
            return
          end
        end
      end

      if http_method == 'POST'
        qvars = queryparse(datastore['DATA']) #Now its a Hash
      else
        qvars = queryparse(datastore['QUERY']) #Now its a Hash
      end
    end
  end
end
