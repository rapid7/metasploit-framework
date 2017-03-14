function GetSubfolders($root) {
  $folders = @()
  $folders += $root
  foreach ($folder in $root.Folders) {
    $folders += GetSubfolders($folder)
  }
  return $folders
}

function List-Folder {
  Clear-host
  Add-Type -Assembly "Microsoft.Office.Interop.Outlook"
  $Outlook = New-Object -ComObject Outlook.Application
  $Namespace = $Outlook.GetNameSpace("MAPI")
  $account = $NameSpace.Folders
  $folders = @()
  foreach ($acc in $account) {
    foreach ($folder in $acc.Folders) {
      $folders += GetSubfolders($folder)
    }
  }
  $folders | FT FolderPath
}

function Get-Emails {
  param ([String]$searchTerm,[String]$Folder)
  Add-Type -Assembly "Microsoft.Office.Interop.Outlook"
  $Outlook = New-Object -ComObject Outlook.Application
  $Namespace = $Outlook.GetNameSpace("MAPI")
  $account = $NameSpace.Folders
  $found = $false
  foreach ($acc in $account) {
    try {
      $Email = $acc.Folders.Item($Folder).Items
      $result = $Email | Where-Object {$_.HTMLBody -like '*' + $searchTerm + '*' -or $_.TaskSubject -like '*' + $searchTerm + '*'}
      if($result) {
        $found = $true
        $result | Format-List To, SenderEmailAddress, CreationTime, TaskSubject, HTMLBody
      }
    } catch {
      Write-Host "Folder" $Folder "not found in mailbox" $acc.Name
    }
  }
  if(-Not $found) {
    Write-Host "Searchterm" $searchTerm "not found"
  }
}
