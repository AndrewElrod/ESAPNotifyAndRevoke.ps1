<#--------HEADER--------
Name: ESAPRevokeAndNotify.ps1
Purpose: Automatically notifies ESAP enabled users when ESAP is 14/30/60 days from expiration, and revokes 365 days after configuration if not renewed.

Created from: $null
Created by: AElrod
Created date: 3/27/2024
Production Date: 5/1/2024

-----CHANGELOG-----
20240327 - Log init
20240426 - Successful test against internal team (4 devices per)
20240428 - Replaced domain information with contoso.com

#>

#Modules
Import-Module ActiveDirectory

#Define dates for script detect conditions
$revokedate = (get-date).Date.AddHours(23).AddMinutes(59).AddSeconds(59)
$14day = (get-date).adddays(14).Date.AddHours(23).AddMinutes(59).AddSeconds(59)
$30day = (get-date).adddays(30).Date.AddHours(23).AddMinutes(59).AddSeconds(59)
$60day = (get-date).adddays(60).Date.AddHours(23).AddMinutes(59).AddSeconds(59)


<#Detect workstations configured for ESAP that meet the script conditions#>

#Get all computers in the MDS Devices container with a populated ManagedBy Attribute
$computers = get-adcomputer -searchbase "OU=Devices,OU=DOMAIN,DC=contoso,DC=con" -filter * -Properties Managedby, AccountExpirationDate | Where-Object { $_.Managedby -ne $null } | Where-Object { $_.AccountExpirationDate -ne $null } | select-object name, distinguishedname, managedby, AccountExpirationDate

#workstation and user object queries, build array
ForEach ($computer in $Computers) { 
    $userid = $null
    $email = $null
    $expirationdate = $null
    $computername = $computer.name

    try { $userID = get-aduser $computer.Managedby -properties samaccountname | select-object -expandproperty samaccountname }
    catch { $userid = get-adgroup $computer.managedby -properties Name | select-object -expandproperty name }
    try {
        $expirationdate = get-adcomputer $computer.distinguishedname -Properties AccountExpirationDate | select-object -ExpandProperty AccountExpirationDate
        $expirationdate = $expirationdate.AddDays(-1)
    }
    catch { $expirationdate = $null }
    try { $email = get-aduser $computer.Managedby -Properties emailaddress | select-object -expandproperty emailaddress }
    catch { $email = "Security Group Managed" }

    $computer | Add-Member -MemberType NoteProperty -Name UsersAMAccountname -Value $userID.ToUpper()
    $computer | Add-Member -MemberType NoteProperty -Name EmailAddress -Value $email.ToLower()
    $computer | Add-Member -MemberType NoteProperty -Name ExpirationString -Value $expirationdate
     
} 

<#End Detection Logic#>

#Filter array for devices that meet the notification and revocation criteria
$revokecomputers = $computers | Where-Object { $_.ExpirationString -eq "$revokedate" }
$14daynotify = $computers | Where-Object { $_.ExpirationString -eq "$14day" }
$30daynotify = $computers | Where-Object { $_.ExpirationString -eq "$30day" }
$60daynotify = $computers | Where-Object { $_.ExpirationString -eq "$60day" }

#Send notificiation emails for ESAP expiration at AddDays -14, -30, and -60 days
foreach ($user in $14daynotify) {
    $emailaddress = $user.emailaddress
    $computername = $user.Name
    $expirationdate = $user.AccountExpirationDate
    $body = "Please be advised that the elevated privileges configured for $emailaddress on $computername are scheduled to expire on $expirationdate.  To prevent an interruption in service, please visit the Customer Portal at http://servicenowservices.contoso.com/contoso to submit a renewal request."

    $options = @{
        'smtpserver' = "smtp.contoso.com"
        'to'         = $emailaddress
        'from'       = "IT Department <ITDepartment@contoso.com"
        'subject'    = "14 ESAP Expiration Notification for $computername - Expires on $expirationdate"
        'body'       = $body
    }
    
    #Send Email with reports
    send-mailmessage @options
}

foreach ($user in $30daynotify) {
    $emailaddress = $user.emailaddress
    $computername = $user.Name
    $expirationdate = $user.AccountExpirationDate
    $body = "Please be advised that the elevated privileges configured for $emailaddress on $computername are scheduled to expire on $expirationdate.  To prevent an interruption in service, please visit the Customer Portal at http://servicenowservices.contoso.com/contoso to submit a renewal request."

    $options = @{
        'smtpserver' = "smtp.contoso.com"
        'to'         = $emailaddress
        'from'       = "IT Department <ITDepartment@contoso.com"
        'subject'    = "30 ESAP Expiration Notification for $computername - Expires on $expirationdate"
        'body'       = $body
    }
    
    #Send Email with reports
    send-mailmessage @options
}

foreach ($user in $60daynotify) {
    $emailaddress = $user.emailaddress
    $computername = $user.Name
    $expirationdate = $user.AccountExpirationDate
    $body = "Please be advised that the elevated privileges configured for $emailaddress on $computername are scheduled to expire on $expirationdate.  To prevent an interruption in service, please visit the Customer Portal at http://servicenowservices.contoso.com/contoso to submit a renewal request."

    $options = @{
        'smtpserver' = "smtp.contoso.com"
        'to'         = $emailaddress
        'from'       = "IT Department <ITDepartment@contoso.com"
        'subject'    = "60 ESAP Expiration Notification for $computername - Expires on $expirationdate"
        'body'       = $body
    }
    
    #Send Email with reports
    send-mailmessage @options
}

#Remove user from ManagedBy and $null AccountExpirationDate if expired
foreach ($computer in $revokecomputers) { set-adcomputer $computer.name -AccountExpirationDate $null -Managedby $null }

<#reporting - not setup yet
$reportdate = get-date -format yyyyddMM
$revokecomputers | export-csv "\\server\share\ESAP_Revoked_$reportdate.csv"
$14daynotify | export-csv "\\server\share\ESAP_Notify_14_$reportdate.csv"
$30daynotify | Export-Csv "\\server\share\ESAP_Notify_30_$reportdate.csv"
$60daynotify | Export-Csv "\\server\share\ESAP_Notify_60_$reportdate.csv"
#>
