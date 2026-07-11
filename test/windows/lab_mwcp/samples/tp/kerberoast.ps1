$filter = "(&(objectClass=user)(servicePrincipalName=*))"
$spns = Get-ADUser -LDAPFilter $filter -Properties ServicePrincipalName
foreach ($spn in $spns) {
  $token = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $spn.ServicePrincipalName
}
