$ou = "AD:\OU=Users,DC=example,DC=ru"
$group = Get-ADGroup resetme
$sid = new-object System.Security.Principal.SecurityIdentifier $group.SID
$ResetPassword = [GUID]"00299570-246d-11d0-a768-00aa006e0529"
$UserObjectType = "bf967aba-0de6-11d0-a285-00aa003049e2"
$ACL = get-acl $OU
$RuleResetPassword = New-Object System.DirectoryServices.ActiveDirectoryAccessRule ($sid, "ExtendedRight", "Allow", $ResetPassword, "Descendents", $UserObjectType)
$ACL.AddAccessRule($RuleResetPassword)
Set-Acl -Path $OU -AclObject $ACL