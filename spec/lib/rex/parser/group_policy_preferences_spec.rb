require 'rex/parser/group_policy_preferences'

xml_group = '
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="SuperSecretBackdoor" image="0" changed="2013-04-25 18:36:07" uid="{B5EDB865-34F5-4BD7-9C59-3AEB1C7A68C3}"><Properties action="C" fullName="" description="" cpassword="VBQUNbDhuVti3/GHTGHPvcno2vH3y8e8m1qALVO1H3T0rdkr2rub1smfTtqRBRI3" changeLogon="0" noChange="0" neverExpires="1" acctDisabled="0" userName="SuperSecretBackdoor"/></User>
</Groups>
'

xml_datasrc = '
<?xml version="1.0" encoding="utf-8"?>
<DataSources clsid="{380F820F-F21B-41ac-A3CC-24D4F80F067B}"><DataSource clsid="{5C209626-D820-4d69-8D50-1FACD6214488}" userContext="1" name="test" image="0" changed="2013-04-25 20:39:08" uid="{3513F923-9661-4819-9995-91A63C7D7A65}"><Properties action="C" userDSN="0" dsn="test" driver="test" description="" username="test" cpassword="eYbbv1GZI4DZEgTXPUDspw"><Attributes><Attribute name="test" value="test"/><Attribute name="test2" value="test2"/></Attributes></Properties></DataSource>
</DataSources>
'

xml_drive = '
<?xml version="1.0" encoding="utf-8"?>
<Drives clsid="{8FDDCC1A-0C3C-43cd-A6B4-71A6DF20DA8C}"><Drive clsid="{935D1B74-9CB8-4e3c-9914-7DD559B7A417}" name="E:" status="E:" image="0" changed="2013-04-25 20:33:02" uid="{016E2095-EAB5-43C0-8BCF-4C2655F709F5}"><Properties action="C" thisDrive="NOCHANGE" allDrives="NOCHANGE" userName="drivemap" path="drivemap" label="" persistent="0" useLetter="1" letter="E" cpassword="Lj3fkZ8E3AFAJPTSoBitKw"/></Drive>
</Drives>
'

xml_schd = '
<?xml version="1.0" encoding="utf-8"?>
<ScheduledTasks clsid="{CC63F200-7309-4ba0-B154-A71CD118DBCC}"><Task clsid="{2DEECB1C-261F-4e13-9B21-16FB83BC03BD}" name="test1" image="2" changed="2013-04-25 20:30:13" uid="{41059D76-C7B4-4D05-9679-AE7510247B1F}"><Properties action="U" name="test1" appName="notepad.exe" args="" startIn="" comment="" runAs="test1" cpassword="DdGgLn/bpUNU/QjjcNvn4A" enabled="0"><Triggers><Trigger type="DAILY" startHour="8" startMinutes="0" beginYear="2013" beginMonth="4" beginDay="25" hasEndDate="0" repeatTask="0" interval="1"/></Triggers></Properties></Task>
</ScheduledTasks>
'

xml_serv = '
<?xml version="1.0" encoding="utf-8"?>
<NTServices clsid="{2CFB484A-4E96-4b5d-A0B6-093D2F91E6AE}"><NTService clsid="{AB6F0B67-341F-4e51-92F9-005FBFBA1A43}" name="Blah" image="0" changed="2013-04-25 20:29:49" uid="{C6AE4201-9F99-46AB-93C2-9D734D87D343}"><Properties startupType="NOCHANGE" serviceName="Blah" timeout="30" accountName="bob" cpassword="OQWR9sf5FTlGgh8SJX31ug"/></NTService>
</NTServices>
'

xml_ms = '
<?xml version="1.0" encoding="utf-8"?>
<Groups   clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}" 
          disabled="1">
  <User   clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" 
          name="DbAdmin" 
          image="2" 
          changed="2007-07-06 20:45:20" 
          uid="{253F4D90-150A-4EFB-BCC8-6E894A9105F7}">
    <Properties 
          action="U" 
          newName="" 
          fullName="Database Admin" 
          description="Local Database Admin" 
          cpassword="demo" 
          changeLogon="0" 
          noChange="0" 
          neverExpires="0" 
          acctDisabled="1" 
          userName="DbAdmin"/>
  </User>
  <Group  clsid="{6D4A79E4-529C-4481-ABD0-F5BD7EA93BA7}" 
          name="Database Admins" 
          image="2" 
          changed="2007-07-06 20:46:21" 
          uid="{C5FB3901-508A-4A9E-9171-60D4FC2B404B}">
    <Properties 
          action="U" 
          newName="" 
          description="Local Database Admins" 
          userAction="REMOVE" 
          deleteAllUsers="1" 
          deleteAllGroups="1" 
          removeAccounts="0" 
          groupName="Database Admins">
      <Members>
        <Member 
          name="domain\sampleuser" 
          action="ADD" 
          sid=""/>
      </Members>
    </Properties>
  </Group>
</Groups>
'

cpassword_normal = "j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw"
cpassword_bad = "blah"

describe Rex::Parser::GPP do
	GPP = Rex::Parser::GPP
	
	##
	# Decrypt
	##
	it "Decrypt returns Local*P4ssword! for normal cpassword" do 
		result = GPP.decrypt(cpassword_normal) 
		result.should eq("Local*P4ssword!")
	end

	it "Decrypt returns blank for bad cpassword" do
		result = GPP.decrypt(cpassword_bad)
		result.should eq("")
	end
	
	it "Decrypt returns blank for nil cpassword" do 
		result = GPP.decrypt(nil)
		result.should eq("")
	end

	##
	# Parse
	##

	it "Parse returns empty [] for nil" do
		GPP.parse(nil).should be_empty
	end

	it "Parse returns results for xml_ms and password is empty" do
		results = GPP.parse(xml_ms)
		results.should_not be_empty
		results[0][:PASS].should be_empty
	end

	it "Parse returns results for xml_datasrc, and attributes, and password is test1" do
		results = GPP.parse(xml_datasrc)
		results.should_not be_empty
		results[0].include?(:ATTRIBUTES).should be_true
		results[0][:ATTRIBUTES].should_not be_empty
		results[0][:PASS].should eq("test")
	end

	xmls = []
	xmls << xml_group
	xmls << xml_drive
	xmls << xml_schd
	xmls << xml_serv
	xmls << xml_datasrc

	it "Parse returns results for all good xmls and passwords" do
		xmls.each do |xml|
			results = GPP.parse(xml)
			results.should_not be_empty
			results[0][:PASS].should_not be_empty
		end
	end

	##
	# Create_Tables
	##
	it "Create_tables returns tables for all good xmls" do
		xmls.each do |xml|
			results = GPP.parse(xml)
			tables = GPP.create_tables(results, "test")
			tables.should_not be_empty
		end
	end
end
