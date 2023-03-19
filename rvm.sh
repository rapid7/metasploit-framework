#!/usr/bin/env bash

shopt -s extglob
set -o errtrace
set -o errexit
set -o pipefail

rvm_install_initialize()
{
  DEFAULT_SOURCES=(github.com/rvm/rvm bitbucket.org/mpapis/rvm)

  BASH_MIN_VERSION="3.2.25"
  if
    [[ -n "${BASH_VERSION:-}" &&
      "$(\printf "%b" "${BASH_VERSION:-}\n${BASH_MIN_VERSION}\n" | LC_ALL=C \sort -t"." -k1,1n -k2,2n -k3,3n | \head -n1)" != "${BASH_MIN_VERSION}"
    ]]
  then
    echo "BASH ${BASH_MIN_VERSION} required (you have $BASH_VERSION)"
    exit 1
  fi

  export HOME PS4
  export rvm_trace_flag rvm_debug_flag rvm_user_install_flag rvm_ignore_rvmrc rvm_prefix rvm_path

  PS4="+ \${BASH_SOURCE##\${rvm_path:-}} : \${FUNCNAME[0]:+\${FUNCNAME[0]}()}  \${LINENO} > "
}

log()  { printf "%b\n" "$*"; }
debug(){ [[ ${rvm_debug_flag:-0} -eq 0 ]] || printf "%b\n" "$*" >&2; }
warn() { log "WARN: $*" >&2 ; }
fail() { fail_with_code 1 "$*" ; }
fail_with_code() { code="$1" ; shift ; log "\nERROR: $*\n" >&2 ; exit "$code" ; }

rvm_install_commands_setup()
{
  \which which >/dev/null 2>&1 || fail "Could not find 'which' command, make sure it's available first before continuing installation."
  \which grep >/dev/null 2>&1 || fail "Could not find 'grep' command, make sure it's available first before continuing installation."
  if
    [[ -z "${rvm_tar_command:-}" ]] && builtin command -v gtar >/dev/null
  then
    rvm_tar_command=gtar
  elif
    ${rvm_tar_command:-tar} --help 2>&1 | GREP_OPTIONS="" \grep -- --strip-components >/dev/null
  then
    rvm_tar_command="${rvm_tar_command:-tar}"
  else
    case "$(uname)" in
      (OpenBSD)
        log "Trying to install GNU version of tar, might require sudo password"
        if (( UID ))
        then sudo pkg_add -z gtar-1
        else pkg_add -z gtar-1
        fi
        rvm_tar_command=gtar
        ;;
      (Darwin|FreeBSD|DragonFly) # it's not possible to autodetect on OSX, the help/man does not mention all flags
        rvm_tar_command=tar
        ;;
      (SunOS)
        case "$(uname -r)" in
          (5.10)
            log "Trying to install GNU version of tar, might require sudo password"
            if (( UID ))
            then
              if \which sudo >/dev/null 2>&1
              then sudo_10=sudo
              elif \which /opt/csw/bin/sudo >/dev/null 2>&1
              then sudo_10=/opt/csw/bin/sudo
              else fail "sudo is required but not found. You may install sudo from OpenCSW repository (https://www.opencsw.org/about)"
              fi
              pkginfo -q CSWpkgutil || $sudo_10 pkgadd -a $rvm_path/config/solaris/noask -d https://get.opencsw.org/now CSWpkgutil
              sudo /opt/csw/bin/pkgutil -iy CSWgtar -t https://mirror.opencsw.org/opencsw/unstable
            else
              pkginfo -q CSWpkgutil || pkgadd -a $rvm_path/config/solaris/noask -d https://get.opencsw.org/now CSWpkgutil
              /opt/csw/bin/pkgutil -iy CSWgtar -t https://mirror.opencsw.org/opencsw/unstable
            fi
            rvm_tar_command=/opt/csw/bin/gtar
            ;;
          (*)
            rvm_tar_command=tar
            ;;
        esac
    esac
    builtin command -v ${rvm_tar_command:-gtar} >/dev/null ||
    fail "Could not find GNU compatible version of 'tar' command, make sure it's available first before continuing installation."
  fi
  if
    [[ " ${rvm_tar_options:-} " != *" --no-same-owner "*  ]] &&
    $rvm_tar_command --help 2>&1 | GREP_OPTIONS="" \grep -- --no-same-owner >/dev/null
  then
    rvm_tar_options="${rvm_tar_options:-}${rvm_tar_options:+ }--no-same-owner"
  fi
}

usage()
{
  printf "%b" "

Usage

  rvm-installer [options] [action]

Options

  [[--]version] <version>

    The version or tag to install. Valid values are:

      latest         - The latest tagged version.
      latest-minor   - The latest minor version of the current major version.
      latest-<x>     - The latest minor version of version x.
      latest-<x>.<y> - The latest patch version of version x.y.
      <x>.<y>.<z>    - Major version x, minor version y and patch z.

  [--]branch <branch>

    The name of the branch from which RVM is installed. This option can be used
    with the following formats for <branch>:

      <account>/

        If account is rvm or mpapis, installs from one of the following:

          https://github.com/rvm/rvm/archive/master.tar.gz
          https://bitbucket.org/mpapis/rvm/get/master.tar.gz

       Otherwise, installs from:

         https://github.com/<account>/rvm/archive/master.tar.gz

      <account>/<branch>

        If account is rvm or mpapis, installs from one of the following:

          https://github.com/rvm/rvm/archive/<branch>.tar.gz
          https://bitbucket.org/mpapis/rvm/get/<branch>.tar.gz

        Otherwise, installs from:

          https://github.com/<account>/rvm/archive/<branch>.tar.gz

      [/]<branch>

        Installs the branch from one of the following:

          https://github.com/rvm/rvm/archive/<branch>.tar.gz
          https://bitbucket.org/mpapis/rvm/get/<branch>.tar.gz

      [--]source <source>

        Defines the repository from which RVM is retrieved and installed in the format:

          <domain>/<account>/<repo>

        Where:

          <domain>  - Is bitbucket.org, github.com or a github enterprise site serving
                      an RVM repository.
          <account> - Is the user account in which the RVM repository resides.
          <repo>    - Is the name of the RVM repository.

        Note that when using the [--]source option, one should only use the [/]branch format
        with the [--]branch option. Failure to do so will result in undefined behavior.

      --trace

        Provides debug logging for the installation script.
Actions

  master - Installs RVM from the master branch at rvm/rvm on github or mpapis/rvm
           on bitbucket.org.
  stable - Installs RVM from the stable branch a rvm/rvm on github or mpapis/rvm
           on bitbucket.org.
  help   - Displays this output.

"
}

## duplication marker 32fosjfjsznkjneuera48jae
__rvm_curl_output_control()
{
  if
    (( ${rvm_quiet_curl_flag:-0} == 1 ))
  then
    __flags+=( "--silent" "--show-error" )
  elif
    [[ " $*" == *" -s"* || " $*" == *" --silent"* ]]
  then
    # make sure --show-error is used with --silent
    [[ " $*" == *" -S"* || " $*" == *" -sS"* || " $*" == *" --show-error"* ]] ||
    {
      __flags+=( "--show-error" )
    }
  fi
}

## duplication marker 32fosjfjsznkjneuera48jae
# -S is automatically added to -s
__rvm_curl()
(
  __rvm_which curl >/dev/null ||
  {
    rvm_error "RVM requires 'curl'. Install 'curl' first and try again."
    return 200
  }

  typeset -a __flags
  __flags=( --fail --location --max-redirs 10 )

  [[ "$*" == *"--max-time"* ]] ||
  [[ "$*" == *"--connect-timeout"* ]] ||
    __flags+=( --connect-timeout 30 --retry-delay 2 --retry 3 )

  if [[ -n "${rvm_proxy:-}" ]]
  then __flags+=( --proxy "${rvm_proxy:-}" )
  fi

  __rvm_curl_output_control

  unset curl
  __rvm_debug_command \curl "${__flags[@]}" "$@" || return $?
)

rvm_error()  { printf "ERROR: %b\n" "$*"; }
__rvm_which(){   which "$@" || return $?; true; }
__rvm_debug_command()
{
  debug "Running($#): $*"
  "$@" || return $?
  true
}
rvm_is_a_shell_function()
{
  [[ -t 0 && -t 1 ]] || return $?
  return ${rvm_is_not_a_shell_function:-0}
}

# Searches the tags for the highest available version matching a given pattern.
# fetch_version (github.com/rvm/rvm bitbucket.org/mpapis/rvm) 1.10. -> 1.10.3
# fetch_version (github.com/rvm/rvm bitbucket.org/mpapis/rvm) 1.10. -> 1.10.3
# fetch_version (github.com/rvm/rvm bitbucket.org/mpapis/rvm) 1.    -> 1.11.0
# fetch_version (github.com/rvm/rvm bitbucket.org/mpapis/rvm) ""    -> 2.0.1
fetch_version()
{
  typeset _account _domain _pattern _repo _sources _values _version
  _sources=(${!1})
  _pattern=$2
  for _source in "${_sources[@]}"
  do
    IFS='/' read -r _domain _account _repo <<< "${_source}"
    _version="$(
      fetch_versions ${_domain} ${_account} ${_repo} |
      GREP_OPTIONS="" \grep "^${_pattern:-}" | tail -n 1
    )"
    if
      [[ -n ${_version} ]]
    then
      echo "${_version}"
      return 0
    fi
  done
  fail_with_code 4 "Exhausted all sources trying to fetch version '$version' of RVM!"
}

# Returns a sorted list of most recent tags from a repository
fetch_versions()
{
  typeset _account _domain _repo _url
  _domain=$1
  _account=$2
  _repo=$3
  case ${_domain} in
    (bitbucket.org)
      _url="https://api.${_domain}/2.0/repositories/${_account}/${_repo}/refs/tags?sort=-name&pagelen=20"
      ;;
    (github.com)
      _url=https://api.${_domain}/repos/${_account}/${_repo}/tags
      ;;

    (*)
      _url=https://${_domain}/api/v3/repos/${_account}/${_repo}/tags
      ;;
  esac

  { __rvm_curl -sS "${_url}" || warn "...the preceeding error with code $? occurred while fetching $_url" ; } |
    \awk -v RS=',|values":' -v FS='"' '$2=="name"&&$4!="rvm"{print $4}' |
    sort -t. -k 1,1n -k 2,2n -k 3,3n -k 4,4n -k 5,5n
}

install_release()
{
  typeset _source _sources _url _version _verify_pgp
  _sources=(${!1})
  _version=$2
  debug "Downloading RVM version ${_version}"
  for _source in "${_sources[@]}"
  do
    case ${_source} in
      (bitbucket.org*)
        _url="https://${_source}/get/${_version}.tar.gz"
        _verify_pgp="https://${_source}/downloads/${_version}.tar.gz.asc"
        ;;
      (*)
        _url="https://${_source}/archive/${_version}.tar.gz"
        _verify_pgp="https://${_source}/releases/download/${_version}/${_version}.tar.gz.asc"
        ;;
    esac
    get_and_unpack "${_url}" "rvm-${_version}.tgz" "$_verify_pgp" && return
  done
  return $?
}

install_head()
{
  typeset _branch _source _sources _url
  _sources=(${!1})
  _branch=$2
  debug "Selected RVM branch ${_branch}"
  for _source in "${_sources[@]}"
  do
    case ${_source} in
      (bitbucket.org*)
        _url=https://${_source}/get/${_branch}.tar.gz
        ;;
      (*)
        _url=https://${_source}/archive/${_branch}.tar.gz
        ;;
    esac
    get_and_unpack "${_url}" "rvm-${_branch//\//_}.tgz" && return
  done
  return $?
}

# duplication marker dfkjdjngdfjngjcszncv
# Drop in cd which _doesn't_ respect cdpath
__rvm_cd()
{
  typeset old_cdpath ret
  ret=0
  old_cdpath="${CDPATH}"
  CDPATH="."
  chpwd_functions="" builtin cd "$@" || ret=$?
  CDPATH="${old_cdpath}"
  return $ret
}

get_package()
{
  typeset _url _file
  _url="$1"
  _file="$2"
  log "Downloading ${_url}"
  __rvm_curl -sS ${_url} > ${rvm_archives_path}/${_file} ||
  {
    _return=$?
    case $_return in
      # duplication marker lfdgzkngdkjvnfjknkjvcnbjkncvjxbn
      (60)
        log "
Could not download '${_url}', you can read more about it here:
https://rvm.io/support/fixing-broken-ssl-certificates/
To continue in insecure mode run 'echo insecure >> ~/.curlrc'.
"
        ;;
      # duplication marker lfdgzkngdkjvnfjknkjvcnbjkncvjxbn
      (77)
        log "
It looks like you have old certificates, you can read more about it here:
https://rvm.io/support/fixing-broken-ssl-certificates/
"
        ;;
      # duplication marker lfdgzkngdkjvnfjknkjvcnbjkncvjxbn
      (141)
        log "
Curl returned 141 - it is result of a segfault which means it's Curls fault.
Try again and if it crashes more than a couple of times you either need to
reinstall Curl or consult with your distribution manual and contact support.
"
        ;;
      (*)
        log "
Could not download '${_url}'.
  curl returned status '$_return'.
"
        ;;
    esac
    return $_return
  }
}

# duplication marker flnglfdjkngjndkfjhsbdjgfghdsgfklgg
rvm_install_gpg_setup()
{
  export rvm_gpg_command
  {
    rvm_gpg_command="$( \which gpg2 2>/dev/null )" &&
    [[ ${rvm_gpg_command} != "/cygdrive/"* ]]
  } || {
    rvm_gpg_command="$( \which gpg 2>/dev/null )" &&
    [[ ${rvm_gpg_command} != "/cygdrive/"* ]]
  } || rvm_gpg_command=""

  debug "Detected GPG program: '$rvm_gpg_command'"

  [[ -n "$rvm_gpg_command" ]] || return $?
}

# duplication marker rdjgndfnghdfnhgfdhbghdbfhgbfdhbn
verify_package_pgp()
{
  if
    "${rvm_gpg_command}" --verify "$2" "$1"
  then
    log "GPG verified '$1'"
  else
    typeset _return=$?

    log "\
GPG signature verification failed for '$1' - '$3'! Try to install GPG v2 and then fetch the public key:

    ${SUDO_USER:+sudo }${rvm_gpg_command##*/} --keyserver hkp://keyserver.ubuntu.com --recv-keys 409B6B1796C275462A1703113804BB82D39DC0E3 7D2BAF1CF37B13E2069D6956105BD0E739499BDB

or if it fails:

    command curl -sSL https://rvm.io/mpapis.asc | ${SUDO_USER:+sudo }${rvm_gpg_command##*/} --import -
    command curl -sSL https://rvm.io/pkuczynski.asc | ${SUDO_USER:+sudo }${rvm_gpg_command##*/} --import -

In case of further problems with validation please refer to https://rvm.io/rvm/security
"

    exit ${_return}
  fi
}

verify_pgp()
{
  [[ -n "${1:-}" ]] ||
  {
    debug "No PGP url given, skipping."
    return 0
  }

  get_package "$1" "$2.asc" ||
  {
    debug "PGP url given but does not exist: '$1'"
    return 0
  }

  rvm_install_gpg_setup ||
  {
    log "Found PGP signature at: '$1',
but no GPG software exists to validate it, skipping."
    return 0
  }

  verify_package_pgp "${rvm_archives_path}/$2" "${rvm_archives_path}/$2.asc" "$1"
}

get_and_unpack()
{
  typeset _url _file _patern _return _verify_pgp
  _url="$1"
  _file="$2"
  _verify_pgp="$3"

  get_package "$_url" "$_file" || return $?
  verify_pgp "$_verify_pgp" "$_file" || return $?

  [[ -d "${rvm_src_path}/rvm" ]] || \mkdir -p "${rvm_src_path}/rvm"
  __rvm_cd "${rvm_src_path}/rvm" ||
  {
    _return=$?
    log "Could not change directory '${rvm_src_path}/rvm'."
    return $_return
  }

  # Remove existing installation
  typeset _cleanup_cmd
  _cleanup_cmd="rm -rf ${rvm_src_path}/rvm/{,.[!.],..?}*"

  $_cleanup_cmd || {
    _return=$?
      log "Could not remove old RVM sources. Try:\n\n\tsudo $_cleanup_cmd\n\nThen retry your task again."
      return $_return
  }

  # Unpack sources
  __rvm_debug_command $rvm_tar_command xzf ${rvm_archives_path}/${_file} ${rvm_tar_options:-} --strip-components 1 ||
  {
    _return=$?
    log "Could not extract RVM sources."
    return $_return
  }
}

rvm_install_default_settings()
{
  # Tracing, if asked for.
  if
    [[ "$*" == *--trace* ]] || (( ${rvm_trace_flag:-0} > 0 ))
  then
    set -o xtrace
    rvm_trace_flag=1
  fi

  # Variable initialization, remove trailing slashes if they exist on HOME
  true \
    ${rvm_trace_flag:=0} ${rvm_debug_flag:=0}\
    ${rvm_ignore_rvmrc:=0} HOME="${HOME%%+(\/)}"

  if
    (( rvm_ignore_rvmrc == 0 ))
  then
    for rvmrc in /etc/rvmrc "$HOME/.rvmrc"
    do
      if
        [[ -s "$rvmrc" ]]
      then
        if
          GREP_OPTIONS="" \grep '^\s*rvm .*$' "$rvmrc" >/dev/null 2>&1
        then
          printf "%b" "
  Error: $rvmrc is for rvm settings only.
  rvm CLI may NOT be called from within $rvmrc.
  Skipping the loading of $rvmrc
  "
          exit 1
        else
          source "$rvmrc"
        fi
      fi
    done
  fi

  if
    [[ -z "${rvm_path:-}" ]]
  then
    if
      (( UID == 0 ))
    then
      rvm_user_install_flag=0
      rvm_prefix="/usr/local"
      rvm_path="${rvm_prefix}/rvm"
    else
      rvm_user_install_flag=1
      rvm_prefix="$HOME"
      rvm_path="${rvm_prefix}/.rvm"
    fi
  fi
  if [[ -z "${rvm_prefix}" ]]
  then rvm_prefix=$( dirname $rvm_path )
  fi

  # duplication marker kkdfkgnjfndgjkndfjkgnkfjdgn
  [[ -n "${rvm_user_install_flag:-}" ]] ||
  case "$rvm_path" in
    (/usr/local/rvm)         rvm_user_install_flag=0 ;;
    ($HOME/*|/${USER// /_}*) rvm_user_install_flag=1 ;;
    (*)                      rvm_user_install_flag=0 ;;
  esac
}

rvm_install_parse_params()
{
  install_rubies=()
  install_gems=()
  flags=( ./scripts/install )
  forwarded_flags=()
  while
    (( $# > 0 ))
  do
    token="$1"
    shift
    case "$token" in

      (--trace)
        set -o xtrace
        rvm_trace_flag=1
        flags=( -x "${flags[@]}" "$token" )
        forwarded_flags+=( "$token" )
        ;;

      (--debug|--quiet-curl)
        flags+=( "$token" )
        forwarded_flags+=( "$token" )
        token=${token#--}
        token=${token//-/_}
        export "rvm_${token}_flag"=1
        printf "%b" "Turning on ${token/_/ } mode.\n"
        ;;

      (--path)
        if [[ -n "${1:-}" ]]
        then
          rvm_path="$1"
          shift
        else
          fail "--path must be followed by a path."
        fi
        ;;

      (--branch|branch) # Install RVM from a given branch
        if [[ -n "${1:-}" ]]
        then
          case "$1" in
            (/*)
              branch=${1#/}
              ;;
            (*/)
              branch=master
              if [[ "${1%/}" -ne rvm ]] && [[ "${1%/}" -ne mpapis ]]
              then sources=(github.com/${1%/}/rvm)
              fi
              ;;
            (*/*)
              branch=${1#*/}
              if [[ "${1%%/*}" -ne rvm ]] && [[ "${1%%/*}" -ne mpapis ]]
              then sources=(github.com/${1%%/*}/rvm)
              fi
              ;;
            (*)
              branch="$1"
              ;;
          esac
          shift
        else
          fail "--branch must be followed by a branchname."
        fi
        ;;

      (--source|source)
        if [[ -n "${1:-}" ]]
        then
          if [[ "$1" = */*/* ]]
          then
            sources=($1)
            shift
          else
            fail "--source must be in the format <domain>/<account>/<repo>."
          fi
        else
          fail "--source must be followed by a source."
        fi
        ;;

      (--user-install|--ignore-dotfiles)
        token=${token#--}
        token=${token//-/_}
        export "rvm_${token}_flag"=1
        printf "%b" "Turning on ${token/_/ } mode.\n"
        ;;

      (--auto-dotfiles)
        flags+=( "$token" )
        export "rvm_auto_dotfiles_flag"=1
        printf "%b" "Turning on auto dotfiles mode.\n"
        ;;

      (--auto)
        export "rvm_auto_dotfiles_flag"=1
        printf "%b" "Warning, --auto is deprecated in favor of --auto-dotfiles.\n"
        ;;

      (--verify-downloads)
        if [[ -n "${1:-}" ]]
        then
          export rvm_verify_downloads_flag="$1"
          forwarded_flags+=( "$token" "$1" )
          shift
        else
          fail "--verify-downloads must be followed by level(0|1|2)."
        fi
        ;;

      (--autolibs=*)
        flags+=( "$token" )
        export rvm_autolibs_flag="${token#--autolibs=}"
        forwarded_flags+=( "$token" )
        ;;

      (--without-gems=*|--with-gems=*|--with-default-gems=*)
        flags+=( "$token" )
        value="${token#*=}"
        token="${token%%=*}"
        token="${token#--}"
        token="${token//-/_}"
        export "rvm_${token}"="${value}"
        printf "%b" "Installing RVM ${token/_/ }: ${value}.\n"
        ;;

      (--version|version)
        version="$1"
        shift
        ;;

      (head|master)
        version="head"
        branch="master"
        ;;

      (stable)
        version="latest"
        ;;

      (latest|latest-*|+([[:digit:]]).+([[:digit:]]).+([[:digit:]]))
        version="$token"
        ;;

      (--ruby)
        install_rubies+=( ruby )
        ;;

      (--ruby=*)
        token=${token#--ruby=}
        install_rubies+=( ${token//,/ } )
        ;;

      (--rails)
        install_gems+=( rails )
        ;;

      (--gems=*)
        token=${token#--gems=}
        install_gems+=( ${token//,/ } )
        ;;

      (--add-to-rvm-group)
        export rvm_add_users_to_rvm_group="$1"
        shift
        ;;

      (help)
        usage
        exit 0
        ;;

      (*)
        usage
        exit 1
        ;;

    esac
  done

  if (( ${#install_gems[@]} > 0 && ${#install_rubies[@]} == 0 ))
  then install_rubies=( ruby )
  fi

  true "${version:=head}"
  true "${branch:=master}"

  if [[ -z "${sources[@]}" ]]
  then sources=("${DEFAULT_SOURCES[@]}")
  fi

  rvm_src_path="$rvm_path/src"
  rvm_archives_path="$rvm_path/archives"
  rvm_releases_url="https://rvm.io/releases"
}

rvm_install_validate_rvm_path()
{
  case "$rvm_path" in
    (*[[:space:]]*)
      printf "%b" "
It looks you are one of the happy *space* users (in home dir name),
RVM is not yet fully ready for it, use this trick to fix it:

    sudo mkdir -p /${USER// /_}.rvm
    sudo chown -R \"$USER:\" /${USER// /_}.rvm
    echo \"export rvm_path=/${USER// /_}.rvm\" >> \"$HOME/.rvmrc\"

and start installing again.

"
      exit 2
    ;;
    (/usr/share/ruby-rvm)
      printf "%b" "
It looks you are one of the happy Ubuntu users,
RVM packaged by Ubuntu is old and broken,
follow this link for details how to fix:

  https://stackoverflow.com/a/9056395/497756

"
      [[ "${rvm_uses_broken_ubuntu_path:-no}" == "yes" ]] || exit 3
    ;;
  esac

  if [[ "$rvm_path" != "/"* ]]
  then fail "The rvm install path must be fully qualified. Tried $rvm_path"
  fi
}

rvm_install_validate_volume_mount_mode()
{
  \typeset path partition test_exec

  path=$rvm_path

  # Directory $rvm_path might not exists at this point so we need to traverse the tree upwards
  while [[ -n "$path" ]]
  do
      if [[ -d $path ]]
      then
        partition=`df -P $path | awk 'END{print $1}'`

        test_exec=$(mktemp $path/rvm-exec-test.XXXXXX)
        echo '#!/bin/sh' > "$test_exec"
        chmod +x "$test_exec"

        if ! "$test_exec"
        then
          rm -f "$test_exec"
          printf "%b" "
It looks that scripts located in ${path}, which would be RVM destination ${rvm_path},
are not executable. One of the reasons might be that partition ${partition} holding this location
is mounted in *noexec* mode, which prevents RVM from working correctly. Please verify your setup
and re-mount partition ${partition} without the noexec option."
          exit 2
        fi

        rm -f "$test_exec"
        break
      fi

      path=${path%/*}
  done
}

rvm_install_select_and_get_version()
{
  typeset dir _version_release _version

  for dir in "$rvm_src_path" "$rvm_archives_path"
  do
    [[ -d "$dir" ]] || mkdir -p "$dir"
  done

  _version_release="${version}"
  case "${version}" in
    (head)
      _version_release="${branch}"
      install_head sources[@] ${branch:-master}
      ;;

    (latest)
      _version=$(fetch_version sources[@])
      install_release sources[@] "$_version"
      ;;

    (latest-minor)
      version="$(<"$rvm_path/VERSION")"
      _version=$(fetch_version sources[@] ${version%.*})
      install_release sources[@] "$_version"
      ;;

    (latest-*)
      _version=$(fetch_version sources[@] ${version#latest-})
      install_release sources[@] "$_version"
      ;;

    (+([[:digit:]]).+([[:digit:]]).+([[:digit:]])) # x.y.z
      install_release sources[@] ${version}
      ;;

    (*)
      fail "Something went wrong, unrecognized version '$version'"
      ;;
  esac
  echo "${_version_release}" > "$rvm_path/RELEASE"
}

rvm_install_main()
{
  [[ -f ./scripts/install ]] ||
  {
    log "'./scripts/install' can not be found for installation, something went wrong, it usually means your 'tar' is broken, please report it here: https://github.com/rvm/rvm/issues"
    return 127
  }

  # required flag - path to install
  flags+=( --path "$rvm_path" )
  \command bash "${flags[@]}"
}

rvm_install_ruby_and_gems()
(
  if
    (( ${#install_rubies[@]} > 0 ))
  then
    source ${rvm_scripts_path:-${rvm_path}/scripts}/rvm
    source ${rvm_scripts_path:-${rvm_path}/scripts}/functions/version
    __rvm_print_headline

    for _ruby in ${install_rubies[@]}
    do command rvm "${forwarded_flags[@]}" install ${_ruby}
    done
    # set the first one as default, skip rest
    for _ruby in ${install_rubies[@]}
    do
      rvm "${forwarded_flags[@]}" alias create default ${_ruby}
      break
    done

    for _gem in ${install_gems[@]}
    do rvm "${forwarded_flags[@]}" all do gem install ${_gem}
    done

    printf "%b" "
  * To start using RVM you need to run \`source $rvm_path/scripts/rvm\`
    in all your open shell windows, in rare cases you need to reopen all shell windows.
"

    if
      [[ "${install_gems[*]}" == *"rails"* ]]
    then
      printf "%b" "
  * To start using rails you need to run \`rails new <project_dir>\`.
"
    fi
  fi
)

rvm_install()
{
  rvm_install_initialize
  rvm_install_commands_setup
  rvm_install_default_settings
  rvm_install_parse_params "$@"
  rvm_install_validate_rvm_path
  rvm_install_validate_volume_mount_mode
  rvm_install_select_and_get_version
  rvm_install_main
  rvm_install_ruby_and_gems
}

rvm_install "$@"
