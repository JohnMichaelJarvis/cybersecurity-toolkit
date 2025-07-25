# Requires ActiveDirectory module
Get-ADUser -Filter * -Property * | Select-Object Name, SamAccountName, EmailAddress
