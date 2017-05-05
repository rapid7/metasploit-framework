if [[ -z "$DOT_MSF" ]]; then
  DOT_MSF="/tmp/.msf4"
fi

# check if .msf4 doesn't exist
if [[ ! -d "$DOT_MSF" ]]; then

  # check if root
  if [[ $EUID -eq 0 ]]; then

    # notify user about the folder creation
    read -p "Script is going to make $DOT_MSF directory for docker mount
Proceed? (Y/n)" -n 1 -r
    echo

    if [[ $REPLY =~ ^[Yy]$ ]]; then
      mkdir "$DOT_MSF" && chmod 777 "$DOT_MSF"
    else
      exit 1
    fi

  # if non-root user
  else
    mkdir "$DOT_MSF" && chmod 777 "$DOT_MSF"
  fi
fi
