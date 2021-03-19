PowerShell 7.1.2
Copyright (c) Microsoft Corporation.
                                                                                                                                                                                                                                             https://aka.ms/powershell                                                                                                                                                                                                                    Type 'help' to get help.                                                                                                                                                                                                                                                                                                                                                                                                                                                                  PS C:\Program Files\Notepad++> https://login.live-int.com/ManageLoginKeys.srf                                                                                                                                                                https://login.live-int.com/ManageLoginKeys.srf: The term 'https://login.live-int.com/ManageLoginKeys.srf' is not recognized as a name of a cmdlet, function, script file, or executable program.
Check the spelling of the name, or if a path was included, verify that the path is correct and try again.
PS C:\Program Files\Notepad++> Fhttps://login.live-int.com/ManageLoginKeys.srf
Fhttps://login.live-int.com/ManageLoginKeys.srf: The term 'Fhttps://login.live-int.com/ManageLoginKeys.srf' is not recognized as a name of a cmdlet, function, script file, or executable program.
Check the spelling of the name, or if a path was included, verify that the path is correct and try again.
PS C:\Program Files\Notepad++> CURL https://login.live-int.com/ManageLoginKeys.srf
<?xml version="1.0" encoding="utf-8" ?><S:Envelope xmlns:S="http://www.w3.org/2003/05/soap-envelope" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" xmlns:wsa="http://www.w3.org/2005/08/addressing"><S:Header></S:Header><S:Body xmlns:ps="http://schemas.microsoft.com/Passport/SoapServices/PPCRL"><ps:ManageLoginKeyResponse Success="false"><ps:ServerInfo ServerTime="2021-03-09T22:53:30Z">SN3PPFA29E798A3 2021.03.07.21.31.07</ps:ServerInfo><ps:Error Code="dc2" /><ps:ErrorSubcode>0x80043449</ps:ErrorSubcode></ps:ManageLoginKeyResponse></S:Body></S:Envelope>
PS C:\Program Files\Notepad++>
PS C:\Program Files\Notepad++> CAL
CAL: The term 'CAL' is not recognized as a name of a cmdlet, function, script file, or executable program.
Check the spelling of the name, or if a path was included, verify that the path is correct and try again.
PS C:\Program Files\Notepad++> CURL -  https://login.live-int.com/ManageLoginKeys.srf
curl: option -: is unknown
curl: try 'curl --help' for more information
PS C:\Program Files\Notepad++> Get-Process PWSH

 NPM(K)    PM(M)      WS(M)     CPU(s)      Id  SI ProcessName
 ------    -----      -----     ------      --  -- -----------
     13     6.90      11.12       0.08    4788   2 pwsh
     14     6.97      15.95       0.11    7408   2 pwsh
     13     6.93      13.52       0.11    9848   2 pwsh

PS C:\Program Files\Notepad++> Get-Process PWSH || KILL

 NPM(K)    PM(M)      WS(M)     CPU(s)      Id  SI ProcessName
 ------    -----      -----     ------      --  -- -----------
     13     6.90      11.12       0.08    4788   2 pwsh
     14     6.97      15.95       0.11    7408   2 pwsh
     13     6.93      13.52       0.11    9848   2 pwsh

PS C:\Program Files\Notepad++> Get-Process PWSH |KILL
PS C:\Program Files\Notepad++> Get-Process PWSH
Get-Process: Cannot find a process with the name "PWSH". Verify the process name and call the cmdlet again.
PS C:\Program Files\Notepad++>
PS C:\Program Files\Notepad++>
PS C:\Program Files\Notepad++>
PS C:\Program Files\Notepad++> EXIT /?
/?: The term '/?' is not recognized as a name of a cmdlet, function, script file, or executable program.
Check the spelling of the name, or if a path was included, verify that the path is correct and try again.
PS C:\Program Files\Notepad++> HELP EXI

Name                              Category  Module                    Synopsis
----                              --------  ------                    --------
Exit-PSHostProcess                Cmdlet    Microsoft.PowerShell.Core Closes an interactive session with a local process.
Exit-PSSession                    Cmdlet    Microsoft.PowerShell.Core Ends an interactive session with a remote computer.

PS C:\Program Files\Notepad++> Exit-PSHostProcess -Verbose:$true -InformationAction:(START PWSH -FORCE:$TRUE)
Start-Process: A parameter cannot be found that matches parameter name 'FORCE'.
PS C:\Program Files\Notepad++> Exit-PSHostProcess -Verbose:$true -InformationAction:(START PWSH)
Exit-PSHostProcess: Cannot bind parameter 'InformationAction' to the target. Exception setting "InformationAction": "Cannot convert null to type "System.Management.Automation.ActionPreference" due to enumeration values that are not valid. Specify one of the following enumeration values and try again. The possible enumeration values are "SilentlyContinue,Stop,Continue,Inquire,Ignore,Suspend,Break"."
PS C:\Program Files\Notepad++> Exit-PSHostProcess -Verbose
PS C:\Program Files\Notepad++>
PS C:\Program Files\Notepad++> Exit-PSHostProcess
PS C:\Program Files\Notepad++> Exit-PSHostProcess
PS C:\Program Files\Notepad++> Exit-PSHostProcess
PS C:\Program Files\Notepad++> Exit-PSHostProcess
PS C:\Program Files\Notepad++> Exit-PSHostProcess
PS C:\Program Files\Notepad++> Exit-PSHostProcess Exit-PSHostProcess Exit-PSHostProcess Exit-PSHostProcess Exit-PSHostProcess Exit-PSHostProcess Exit-PSHostProcess Exit-PSHostProcess Exit-PSHostProcess Exit-PSHostProcess Exit-PSHostProcess
Exit-PSHostProcess: A positional parameter cannot be found that accepts argument 'Exit-PSHostProcess'.
PS C:\Program Files\Notepad++> ^C
PS C:\Program Files\Notepad++> ||
ParserError:
Line |
   1 |  ||
     |  ~~
     | Unexpected token '||' in expression or statement.

PS C:\Program Files\Notepad++> Exit-PSHostProcess ||^C
PS C:\Program Files\Notepad++> Exit-PSHostProcess ^C
PS C:\Program Files\Notepad++> ^C
PS C:\Program Files\Notepad++> Exit-PSHostProcess
PS C:\Program Files\Notepad++> Exit-PSHostProcess PWSH
Exit-PSHostProcess: A positional parameter cannot be found that accepts argument 'PWSH'.
PS C:\Program Files\Notepad++> Exit-PSHostProcess PWSH
Exit-PSHostProcess: A positional parameter cannot be found that accepts argument 'PWSH'.
PS C:\Program Files\Notepad++> PS PWSH

 NPM(K)    PM(M)      WS(M)     CPU(s)      Id  SI ProcessName
 ------    -----      -----     ------      --  -- -----------
     66    72.27     109.82       2.11    5872   2 pwsh

PS C:\Program Files\Notepad++> START PY
PS C:\Program Files\Notepad++> START PY
PS C:\Program Files\Notepad++> Get-M365DSCAllResources
PS C:\Program Files\Notepad++> Get-Module

ModuleType Version    PreRelease Name                                ExportedCommands
---------- -------    ---------- ----                                ----------------
Binary     2.0.2.129             AzureADPreview                      {Add-AzureADAdministrativeUnitMember, Add-AzureADApplicationOwner, Add-AzureADApplicationPolicy, Add-AzureADDeviceRegisteredOwner…}
Manifest   1.3.0.0               DSCParser                           {Convert-CIMInstanceToPSObject, ConvertTo-DSCObject, Get-HashtableFromGroup}
Script     2.0.3                 ExchangeOnlineManagement            {Get-EXOCasMailbox, Get-EXOMailbox, Get-EXOMailboxFolderPermission, Get-EXOMailboxFolderStatistics…}
Script     1.3.1                 Microsoft.Graph.Authentication      {Add-MgEnvironment, Connect-MgGraph, Disconnect-MgGraph, Get-MgContext…}
Script     0.9.1                 Microsoft.Graph.Groups.Planner      {Get-MgGroupPlanner, Get-MgGroupPlannerPlan, Get-MgGroupPlannerPlanBucket, Get-MgGroupPlannerPlanBucketTask…}
Manifest   7.0.0.0               Microsoft.PowerShell.Management     {Add-Content, Clear-Content, Clear-Item, Clear-ItemProperty…}
Manifest   7.0.0.0               Microsoft.PowerShell.Utility        {Add-Member, Add-Type, Clear-Variable, Compare-Object…}
Script     2.1.0                 PSReadLine                          {Get-PSReadLineKeyHandler, Get-PSReadLineOption, Remove-PSReadLineKeyHandler, Set-PSReadLineKeyHandler…}

PS C:\Program Files\Notepad++> Get-Module

ModuleType Version    PreRelease Name                                ExportedCommands
---------- -------    ---------- ----                                ----------------
Binary     2.0.2.129             AzureADPreview                      {Add-AzureADAdministrativeUnitMember, Add-AzureADApplicationOwner, Add-AzureADApplicationPolicy, Add-AzureADDeviceRegisteredOwner…}
Manifest   1.3.0.0               DSCParser                           {Convert-CIMInstanceToPSObject, ConvertTo-DSCObject, Get-HashtableFromGroup}
Script     2.0.3                 ExchangeOnlineManagement            {Get-EXOCasMailbox, Get-EXOMailbox, Get-EXOMailboxFolderPermission, Get-EXOMailboxFolderStatistics…}
Script     1.3.1                 Microsoft.Graph.Authentication      {Add-MgEnvironment, Connect-MgGraph, Disconnect-MgGraph, Get-MgContext…}
Script     0.9.1                 Microsoft.Graph.Groups.Planner      {Get-MgGroupPlanner, Get-MgGroupPlannerPlan, Get-MgGroupPlannerPlanBucket, Get-MgGroupPlannerPlanBucketTask…}
Manifest   7.0.0.0               Microsoft.PowerShell.Management     {Add-Content, Clear-Content, Clear-Item, Clear-ItemProperty…}
Manifest   7.0.0.0               Microsoft.PowerShell.Utility        {Add-Member, Add-Type, Clear-Variable, Compare-Object…}
Script     2.1.0                 PSReadLine                          {Get-PSReadLineKeyHandler, Get-PSReadLineOption, Remove-PSReadLineKeyHandler, Set-PSReadLineKeyHandler…}

PS C:\Program Files\Notepad++> Get-Module

ModuleType Version    PreRelease Name                                ExportedCommands
---------- -------    ---------- ----                                ----------------
Binary     2.0.2.129             AzureADPreview                      {Add-AzureADAdministrativeUnitMember, Add-AzureADApplicationOwner, Add-AzureADApplicationPolicy, Add-AzureADDeviceRegisteredOwner…}
Manifest   1.3.0.0               DSCParser                           {Convert-CIMInstanceToPSObject, ConvertTo-DSCObject, Get-HashtableFromGroup}
Script     2.0.3                 ExchangeOnlineManagement            {Get-EXOCasMailbox, Get-EXOMailbox, Get-EXOMailboxFolderPermission, Get-EXOMailboxFolderStatistics…}
Script     1.3.1                 Microsoft.Graph.Authentication      {Add-MgEnvironment, Connect-MgGraph, Disconnect-MgGraph, Get-MgContext…}
Script     0.9.1                 Microsoft.Graph.Groups.Planner      {Get-MgGroupPlanner, Get-MgGroupPlannerPlan, Get-MgGroupPlannerPlanBucket, Get-MgGroupPlannerPlanBucketTask…}
Manifest   7.0.0.0               Microsoft.PowerShell.Management     {Add-Content, Clear-Content, Clear-Item, Clear-ItemProperty…}
Manifest   7.0.0.0               Microsoft.PowerShell.Utility        {Add-Member, Add-Type, Clear-Variable, Compare-Object…}
Script     2.1.0                 PSReadLine                          {Get-PSReadLineKeyHandler, Get-PSReadLineOption, Remove-PSReadLineKeyHandler, Set-PSReadLineKeyHandler…}

PS C:\Program Files\Notepad++> Get-Module

ModuleType Version    PreRelease Name                                ExportedCommands
---------- -------    ---------- ----                                ----------------
Binary     2.0.2.129             AzureADPreview                      {Add-AzureADAdministrativeUnitMember, Add-AzureADApplicationOwner, Add-AzureADApplicationPolicy, Add-AzureADDeviceRegisteredOwner…}
Manifest   1.3.0.0               DSCParser                           {Convert-CIMInstanceToPSObject, ConvertTo-DSCObject, Get-HashtableFromGroup}
Script     2.0.3                 ExchangeOnlineManagement            {Get-EXOCasMailbox, Get-EXOMailbox, Get-EXOMailboxFolderPermission, Get-EXOMailboxFolderStatistics…}
Script     1.3.1                 Microsoft.Graph.Authentication      {Add-MgEnvironment, Connect-MgGraph, Disconnect-MgGraph, Get-MgContext…}
Script     0.9.1                 Microsoft.Graph.Groups.Planner      {Get-MgGroupPlanner, Get-MgGroupPlannerPlan, Get-MgGroupPlannerPlanBucket, Get-MgGroupPlannerPlanBucketTask…}
Manifest   7.0.0.0               Microsoft.PowerShell.Management     {Add-Content, Clear-Content, Clear-Item, Clear-ItemProperty…}
Manifest   7.0.0.0               Microsoft.PowerShell.Utility        {Add-Member, Add-Type, Clear-Variable, Compare-Object…}
Script     2.1.0                 PSReadLine                          {Get-PSReadLineKeyHandler, Get-PSReadLineOption, Remove-PSReadLineKeyHandler, Set-PSReadLineKeyHandler…}

PS C:\Program Files\Notepad++> AzureADPreview\
Add-AzureADAdministrativeUnitMember                                Get-AzureADObjectByObjectId                                        Remove-AzureADDomain
Add-AzureADApplicationOwner                                        Get-AzureADObjectSetting                                           Remove-AzureADExternalDomainFederation
Add-AzureADApplicationPolicy                                       Get-AzureADPolicy                                                  Remove-AzureADGroup
Add-AzureADDeviceRegisteredOwner                                   Get-AzureADPolicyAppliedObject                                     Remove-AzureADGroupAppRoleAssignment
Add-AzureADDeviceRegisteredUser                                    Get-AzureADPrivilegedRole                                          Remove-AzureADGroupMember
Add-AzureADDirectoryRoleMember                                     Get-AzureADPrivilegedRoleAssignment                                Remove-AzureADGroupOwner
Add-AzureADGroupMember                                             Get-AzureADScopedRoleMembership                                    Remove-AzureADMSApplication
Add-AzureADGroupOwner                                              Get-AzureADServiceAppRoleAssignedTo                                Remove-AzureADMSApplicationExtensionProperty
Add-AzureADMSApplicationOwner                                      Get-AzureADServiceAppRoleAssignment                                Remove-AzureADMSApplicationKey
Add-AzureADMSFeatureRolloutPolicyDirectoryObject                   Get-AzureADServicePrincipal                                        Remove-AzureADMSApplicationOwner
Add-AzureADMSLifecyclePolicyGroup                                  Get-AzureADServicePrincipalCreatedObject                           Remove-AzureADMSApplicationPassword
Add-AzureADMSPrivilegedResource                                    Get-AzureADServicePrincipalKeyCredential                           Remove-AzureADMSApplicationVerifiedPublisher
Add-AzureADMSServicePrincipalDelegatedPermissionClassification     Get-AzureADServicePrincipalMembership                              Remove-AzureADMSConditionalAccessPolicy
Add-AzureADScopedRoleMembership                                    Get-AzureADServicePrincipalOAuth2PermissionGrant                   Remove-AzureADMSDeletedDirectoryObject
Add-AzureADServicePrincipalOwner                                   Get-AzureADServicePrincipalOwnedObject                             Remove-AzureADMSFeatureRolloutPolicy
Add-AzureADServicePrincipalPolicy                                  Get-AzureADServicePrincipalOwner                                   Remove-AzureADMSFeatureRolloutPolicyDirectoryObject
Close-AzureADMSPrivilegedRoleAssignmentRequest                     Get-AzureADServicePrincipalPasswordCredential                      Remove-AzureADMSGroup
Confirm-AzureADDomain                                              Get-AzureADServicePrincipalPolicy                                  Remove-AzureADMSGroupLifecyclePolicy
Connect-AzureAD                                                    Get-AzureADSubscribedSku                                           Remove-AzureADMSIdentityProvider
Disconnect-AzureAD                                                 Get-AzureADTenantDetail                                            Remove-AzureADMSLifecyclePolicyGroup
Enable-AzureADDirectoryRole                                        Get-AzureADTrustedCertificateAuthority                             Remove-AzureADMSNamedLocationPolicy
Get-AzureADAdministrativeUnit                                      Get-AzureADUser                                                    Remove-AzureADMSPasswordSingleSignOnCredential
Get-AzureADAdministrativeUnitMember                                Get-AzureADUserAppRoleAssignment                                   Remove-AzureADMSPermissionGrantConditionSet
Get-AzureADApplication                                             Get-AzureADUserCreatedObject                                       Remove-AzureADMSPermissionGrantPolicy
Get-AzureADApplicationExtensionProperty                            Get-AzureADUserDirectReport                                        Remove-AzureADMSRoleAssignment
Get-AzureADApplicationKeyCredential                                Get-AzureADUserExtension                                           Remove-AzureADMSRoleDefinition
Get-AzureADApplicationLogo                                         Get-AzureADUserLicenseDetail                                       Remove-AzureADMSServicePrincipalDelegatedPermissionClassification
Get-AzureADApplicationOwner                                        Get-AzureADUserManager                                             Remove-AzureADMSTrustFrameworkPolicy
Get-AzureADApplicationPasswordCredential                           Get-AzureADUserMembership                                          Remove-AzureADOAuth2PermissionGrant
Get-AzureADApplicationPolicy                                       Get-AzureADUserOAuth2PermissionGrant                               Remove-AzureADObjectSetting
Get-AzureADApplicationProxyApplication                             Get-AzureADUserOwnedDevice                                         Remove-AzureADPolicy
Get-AzureADApplicationProxyApplicationConnectorGroup               Get-AzureADUserOwnedObject                                         Remove-AzureADScopedRoleMembership
Get-AzureADApplicationProxyConnector                               Get-AzureADUserRegisteredDevice                                    Remove-AzureADServiceAppRoleAssignment
Get-AzureADApplicationProxyConnectorGroup                          Get-AzureADUserThumbnailPhoto                                      Remove-AzureADServicePrincipal
Get-AzureADApplicationProxyConnectorGroupMembers                   Get-CrossCloudVerificationCode                                     Remove-AzureADServicePrincipalKeyCredential
Get-AzureADApplicationProxyConnectorMemberOf                       New-AzureADAdministrativeUnit                                      Remove-AzureADServicePrincipalOwner
Get-AzureADApplicationServiceEndpoint                              New-AzureADApplication                                             Remove-AzureADServicePrincipalPasswordCredential
Get-AzureADApplicationSignInDetailedSummary                        New-AzureADApplicationExtensionProperty                            Remove-AzureADServicePrincipalPolicy
Get-AzureADApplicationSignInSummary                                New-AzureADApplicationKeyCredential                                Remove-AzureADTrustedCertificateAuthority
Get-AzureADAuditDirectoryLogs                                      New-AzureADApplicationPasswordCredential                           Remove-AzureADUser
Get-AzureADAuditSignInLogs                                         New-AzureADApplicationProxyApplication                             Remove-AzureADUserAppRoleAssignment
Get-AzureADContact                                                 New-AzureADApplicationProxyConnectorGroup                          Remove-AzureADUserExtension
Get-AzureADContactDirectReport                                     New-AzureADDevice                                                  Remove-AzureADUserManager
Get-AzureADContactManager                                          New-AzureADDirectorySetting                                        Reset-AzureADMSLifeCycleGroup
Get-AzureADContactMembership                                       New-AzureADDomain                                                  Restore-AzureADDeletedApplication
Get-AzureADContactThumbnailPhoto                                   New-AzureADExternalDomainFederation                                Restore-AzureADMSDeletedDirectoryObject
Get-AzureADContract                                                New-AzureADGroup                                                   Revoke-AzureADSignedInUserAllRefreshToken
Get-AzureADCurrentSessionInfo                                      New-AzureADGroupAppRoleAssignment                                  Revoke-AzureADUserAllRefreshToken
Get-AzureADDeletedApplication                                      New-AzureADMSApplication                                           Select-AzureADGroupIdsContactIsMemberOf
Get-AzureADDevice                                                  New-AzureADMSApplicationExtensionProperty                          Select-AzureADGroupIdsGroupIsMemberOf
Get-AzureADDeviceConfiguration                                     New-AzureADMSApplicationFromApplicationTemplate                    Select-AzureADGroupIdsServicePrincipalIsMemberOf
Get-AzureADDeviceRegisteredOwner                                   New-AzureADMSApplicationKey                                        Select-AzureADGroupIdsUserIsMemberOf
Get-AzureADDeviceRegisteredUser                                    New-AzureADMSApplicationPassword                                   Set-AzureADAdministrativeUnit
Get-AzureADDirectoryRole                                           New-AzureADMSConditionalAccessPolicy                               Set-AzureADApplication
Get-AzureADDirectoryRoleMember                                     New-AzureADMSFeatureRolloutPolicy                                  Set-AzureADApplicationLogo
Get-AzureADDirectoryRoleTemplate                                   New-AzureADMSGroup                                                 Set-AzureADApplicationProxyApplication
Get-AzureADDirectorySetting                                        New-AzureADMSGroupLifecyclePolicy                                  Set-AzureADApplicationProxyApplicationConnectorGroup
Get-AzureADDirectorySettingTemplate                                New-AzureADMSIdentityProvider                                      Set-AzureADApplicationProxyApplicationCustomDomainCertificate
Get-AzureADDomain                                                  New-AzureADMSInvitation                                            Set-AzureADApplicationProxyApplicationSingleSignOn
Get-AzureADDomainNameReference                                     New-AzureADMSNamedLocationPolicy                                   Set-AzureADApplicationProxyConnector
Get-AzureADDomainServiceConfigurationRecord                        New-AzureADMSPasswordSingleSignOnCredential                        Set-AzureADApplicationProxyConnectorGroup
Get-AzureADDomainVerificationDnsRecord                             New-AzureADMSPermissionGrantConditionSet                           Set-AzureADDevice
Get-AzureADExtensionProperty                                       New-AzureADMSPermissionGrantPolicy                                 Set-AzureADDirectorySetting
Get-AzureADExternalDomainFederation                                New-AzureADMSRoleAssignment                                        Set-AzureADDomain
Get-AzureADGroup                                                   New-AzureADMSRoleDefinition                                        Set-AzureADGroup
Get-AzureADGroupAppRoleAssignment                                  New-AzureADMSTrustFrameworkPolicy                                  Set-AzureADMSApplication
Get-AzureADGroupMember                                             New-AzureADObjectSetting                                           Set-AzureADMSApplicationLogo
Get-AzureADGroupOwner                                              New-AzureADPolicy                                                  Set-AzureADMSApplicationVerifiedPublisher
Get-AzureADMSApplication                                           New-AzureADPrivilegedRoleAssignment                                Set-AzureADMSAuthorizationPolicy
Get-AzureADMSApplicationExtensionProperty                          New-AzureADServiceAppRoleAssignment                                Set-AzureADMSConditionalAccessPolicy
Get-AzureADMSApplicationOwner                                      New-AzureADServicePrincipal                                        Set-AzureADMSFeatureRolloutPolicy
Get-AzureADMSApplicationTemplate                                   New-AzureADServicePrincipalKeyCredential                           Set-AzureADMSGroup
Get-AzureADMSAuthorizationPolicy                                   New-AzureADServicePrincipalPasswordCredential                      Set-AzureADMSGroupLifecyclePolicy
Get-AzureADMSConditionalAccessPolicy                               New-AzureADTrustedCertificateAuthority                             Set-AzureADMSIdentityProvider
Get-AzureADMSDeletedDirectoryObject                                New-AzureADUser                                                    Set-AzureADMSNamedLocationPolicy
Get-AzureADMSDeletedGroup                                          New-AzureADUserAppRoleAssignment                                   Set-AzureADMSPasswordSingleSignOnCredential
Get-AzureADMSFeatureRolloutPolicy                                  Open-AzureADMSPrivilegedRoleAssignmentRequest                      Set-AzureADMSPermissionGrantConditionSet
Get-AzureADMSGroup                                                 Remove-AzureADAdministrativeUnit                                   Set-AzureADMSPermissionGrantPolicy
Get-AzureADMSGroupLifecyclePolicy                                  Remove-AzureADAdministrativeUnitMember                             Set-AzureADMSPrivilegedRoleAssignmentRequest
Get-AzureADMSGroupPermissionGrant                                  Remove-AzureADApplication                                          Set-AzureADMSPrivilegedRoleSetting
Get-AzureADMSIdentityProvider                                      Remove-AzureADApplicationExtensionProperty                         Set-AzureADMSRoleDefinition
Get-AzureADMSLifecyclePolicyGroup                                  Remove-AzureADApplicationKeyCredential                             Set-AzureADMSTrustFrameworkPolicy
Get-AzureADMSNamedLocationPolicy                                   Remove-AzureADApplicationOwner                                     Set-AzureADObjectSetting
Get-AzureADMSPasswordSingleSignOnCredential                        Remove-AzureADApplicationPasswordCredential                        Set-AzureADPolicy
Get-AzureADMSPermissionGrantConditionSet                           Remove-AzureADApplicationPolicy                                    Set-AzureADServicePrincipal
Get-AzureADMSPermissionGrantPolicy                                 Remove-AzureADApplicationProxyApplication                          Set-AzureADTenantDetail
Get-AzureADMSPrivilegedResource                                    Remove-AzureADApplicationProxyApplicationConnectorGroup            Set-AzureADTrustedCertificateAuthority
Get-AzureADMSPrivilegedRoleAssignment                              Remove-AzureADApplicationProxyConnectorGroup                       Set-AzureADUser
Get-AzureADMSPrivilegedRoleAssignmentRequest                       Remove-AzureADContact                                              Set-AzureADUserExtension
Get-AzureADMSPrivilegedRoleDefinition                              Remove-AzureADContactManager                                       Set-AzureADUserLicense
Get-AzureADMSPrivilegedRoleSetting                                 Remove-AzureADDeletedApplication                                   Set-AzureADUserManager
Get-AzureADMSRoleAssignment                                        Remove-AzureADDevice                                               Set-AzureADUserPassword
Get-AzureADMSRoleDefinition                                        Remove-AzureADDeviceRegisteredOwner                                Set-AzureADUserThumbnailPhoto
Get-AzureADMSServicePrincipalDelegatedPermissionClassification     Remove-AzureADDeviceRegisteredUser                                 Update-AzureADSignedInUserPassword
Get-AzureADMSTrustFrameworkPolicy                                  Remove-AzureADDirectoryRoleMember
Get-AzureADOAuth2PermissionGrant                                   Remove-AzureADDirectorySetting
PS C:\Program Files\Notepad++> AzureADPreview\Add-AzureADAdministrativeUnitMember

cmdlet Add-AzureADAdministrativeUnitMember at command pipeline position 1
Supply values for the following parameters:
ObjectId:
PS C:\Program Files\Notepad++> AzureADPreview\Get-AzureADAdministrativeUnit
Get-AzureADAdministrativeUnit: You must call the Connect-AzureAD cmdlet before calling any other cmdlets.
PS C:\Program Files\Notepad++> AzureADPreview\Connect-AzureAD
Connect-AzureAD: One or more errors occurred. (Could not load type 'System.Security.Cryptography.SHA256Cng' from assembly 'System.Core, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089'.): Could not load type 'System.Security.Cryptography.SHA256Cng' from assembly 'System.Core, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089'.
Connect-AzureAD: One or more errors occurred. (Could not load type 'System.Security.Cryptography.SHA256Cng' from assembly 'System.Core, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089'.)
Connect-AzureAD: Could not load type 'System.Security.Cryptography.SHA256Cng' from assembly 'System.Core, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089'.
Connect-AzureAD: One or more errors occurred. (Could not load type 'System.Security.Cryptography.SHA256Cng' from assembly 'System.Core, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089'.): Could not load type 'System.Security.Cryptography.SHA256Cng' from assembly 'System.Core, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089'.
PS C:\Program Files\Notepad++> h

  Id     Duration CommandLine
  --     -------- -----------
   1        0.273 https://login.live-int.com/ManageLoginKeys.srf
   2        0.048 Fhttps://login.live-int.com/ManageLoginKeys.srf
   3        0.946 CURL https://login.live-int.com/ManageLoginKeys.srf
   4        0.106 CAL
   5        0.059 CURL -  https://login.live-int.com/ManageLoginKeys.srf
   6        0.106 Get-Process PWSH
   7        0.030 Get-Process PWSH || KILL
   8        0.049 Get-Process PWSH |KILL
   9        0.057 Get-Process PWSH
  10        0.080 EXIT /?
  11        0.883 HELP EXI
  12        0.057 Exit-PSHostProcess -Verbose:$true -InformationAction:(START PWSH -FORCE:$TRUE)
  13        0.112 Exit-PSHostProcess -Verbose:$true -InformationAction:(START PWSH)
  14        0.012 Exit-PSHostProcess -Verbose
  15        0.008 Exit-PSHostProcess
  16        0.002 Exit-PSHostProcess
  17        0.002 Exit-PSHostProcess
  18        0.001 Exit-PSHostProcess
  19        0.002 Exit-PSHostProcess
  20        0.046 Exit-PSHostProcess Exit-PSHostProcess Exit-PSHostProcess Exit-PSHostProcess Exit-PSHostProcess Exit-PSHostProcess Exit-PSHostProcess Exit-PSHostProcess Exit-PSHostProcess Exit-PSHostProcess Exit-PSHostProcess
  21        0.000 ||
  22        0.003 Exit-PSHostProcess
  23        0.052 Exit-PSHostProcess PWSH
  24        0.033 Exit-PSHostProcess PWSH
  25        0.047 PS PWSH
  26        0.033 START PY
  27        0.031 START PY
  28        1.073 Get-M365DSCAllResources
  29        0.078 Get-Module
  30        0.038 Get-Module
  31        0.049 Get-Module
  32        0.038 Get-Module
  33        3.805 AzureADPreview\Add-AzureADAdministrativeUnitMember
  34        0.063 AzureADPreview\Get-AzureADAdministrativeUnit
  35       43.877 AzureADPreview\Connect-AzureAD

PS C:\Program Files\Notepad++> Add-Type -ReferencedAssemblies:System.Security.Cryptography.SHA256Cng

cmdlet Add-Type at command pipeline position 1
Supply values for the following parameters:
TypeDefinition: System.Core
Add-Type: Cannot find path 'C:\Program Files\Notepad++\System.Security.Cryptography.SHA256Cng.dll' because it does not exist.
PS C:\Program Files\Notepad++> ([System.Reflection.Metadata.TypeDefinition])

IsPublic IsSerial Name                                     BaseType
-------- -------- ----                                     --------
True     False    TypeDefinition                           System.ValueType

PS C:\Program Files\Notepad++> AzureADPreview\
Add-AzureADAdministrativeUnitMember                                Get-AzureADObjectByObjectId                                        Remove-AzureADDomain
Add-AzureADApplicationOwner                                        Get-AzureADObjectSetting                                           Remove-AzureADExternalDomainFederation
Add-AzureADApplicationPolicy                                       Get-AzureADPolicy                                                  Remove-AzureADGroup
Add-AzureADDeviceRegisteredOwner                                   Get-AzureADPolicyAppliedObject                                     Remove-AzureADGroupAppRoleAssignment
Add-AzureADDeviceRegisteredUser                                    Get-AzureADPrivilegedRole                                          Remove-AzureADGroupMember
Add-AzureADDirectoryRoleMember                                     Get-AzureADPrivilegedRoleAssignment                                Remove-AzureADGroupOwner
Add-AzureADGroupMember                                             Get-AzureADScopedRoleMembership                                    Remove-AzureADMSApplication
Add-AzureADGroupOwner                                              Get-AzureADServiceAppRoleAssignedTo                                Remove-AzureADMSApplicationExtensionProperty
Add-AzureADMSApplicationOwner                                      Get-AzureADServiceAppRoleAssignment                                Remove-AzureADMSApplicationKey
Add-AzureADMSFeatureRolloutPolicyDirectoryObject                   Get-AzureADServicePrincipal                                        Remove-AzureADMSApplicationOwner
Add-AzureADMSLifecyclePolicyGroup                                  Get-AzureADServicePrincipalCreatedObject                           Remove-AzureADMSApplicationPassword
Add-AzureADMSPrivilegedResource                                    Get-AzureADServicePrincipalKeyCredential                           Remove-AzureADMSApplicationVerifiedPublisher
Add-AzureADMSServicePrincipalDelegatedPermissionClassification     Get-AzureADServicePrincipalMembership                              Remove-AzureADMSConditionalAccessPolicy
Add-AzureADScopedRoleMembership                                    Get-AzureADServicePrincipalOAuth2PermissionGrant                   Remove-AzureADMSDeletedDirectoryObject
Add-AzureADServicePrincipalOwner                                   Get-AzureADServicePrincipalOwnedObject                             Remove-AzureADMSFeatureRolloutPolicy
Add-AzureADServicePrincipalPolicy                                  Get-AzureADServicePrincipalOwner                                   Remove-AzureADMSFeatureRolloutPolicyDirectoryObject
Close-AzureADMSPrivilegedRoleAssignmentRequest                     Get-AzureADServicePrincipalPasswordCredential                      Remove-AzureADMSGroup
Confirm-AzureADDomain                                              Get-AzureADServicePrincipalPolicy                                  Remove-AzureADMSGroupLifecyclePolicy
Connect-AzureAD                                                    Get-AzureADSubscribedSku                                           Remove-AzureADMSIdentityProvider
Disconnect-AzureAD                                                 Get-AzureADTenantDetail                                            Remove-AzureADMSLifecyclePolicyGroup
Enable-AzureADDirectoryRole                                        Get-AzureADTrustedCertificateAuthority                             Remove-AzureADMSNamedLocationPolicy
Get-AzureADAdministrativeUnit                                      Get-AzureADUser                                                    Remove-AzureADMSPasswordSingleSignOnCredential
Get-AzureADAdministrativeUnitMember                                Get-AzureADUserAppRoleAssignment                                   Remove-AzureADMSPermissionGrantConditionSet
Get-AzureADApplication                                             Get-AzureADUserCreatedObject                                       Remove-AzureADMSPermissionGrantPolicy
Get-AzureADApplicationExtensionProperty                            Get-AzureADUserDirectReport                                        Remove-AzureADMSRoleAssignment
Get-AzureADApplicationKeyCredential                                Get-AzureADUserExtension                                           Remove-AzureADMSRoleDefinition
Get-AzureADApplicationLogo                                         Get-AzureADUserLicenseDetail                                       Remove-AzureADMSServicePrincipalDelegatedPermissionClassification
Get-AzureADApplicationOwner                                        Get-AzureADUserManager                                             Remove-AzureADMSTrustFrameworkPolicy
Get-AzureADApplicationPasswordCredential                           Get-AzureADUserMembership                                          Remove-AzureADOAuth2PermissionGrant
Get-AzureADApplicationPolicy                                       Get-AzureADUserOAuth2PermissionGrant                               Remove-AzureADObjectSetting
Get-AzureADApplicationProxyApplication                             Get-AzureADUserOwnedDevice                                         Remove-AzureADPolicy
Get-AzureADApplicationProxyApplicationConnectorGroup               Get-AzureADUserOwnedObject                                         Remove-AzureADScopedRoleMembership
Get-AzureADApplicationProxyConnector                               Get-AzureADUserRegisteredDevice                                    Remove-AzureADServiceAppRoleAssignment
Get-AzureADApplicationProxyConnectorGroup                          Get-AzureADUserThumbnailPhoto                                      Remove-AzureADServicePrincipal
Get-AzureADApplicationProxyConnectorGroupMembers                   Get-CrossCloudVerificationCode                                     Remove-AzureADServicePrincipalKeyCredential
Get-AzureADApplicationProxyConnectorMemberOf                       New-AzureADAdministrativeUnit                                      Remove-AzureADServicePrincipalOwner
Get-AzureADApplicationServiceEndpoint                              New-AzureADApplication                                             Remove-AzureADServicePrincipalPasswordCredential
Get-AzureADApplicationSignInDetailedSummary                        New-AzureADApplicationExtensionProperty                            Remove-AzureADServicePrincipalPolicy
Get-AzureADApplicationSignInSummary                                New-AzureADApplicationKeyCredential                                Remove-AzureADTrustedCertificateAuthority
Get-AzureADAuditDirectoryLogs                                      New-AzureADApplicationPasswordCredential                           Remove-AzureADUser
Get-AzureADAuditSignInLogs                                         New-AzureADApplicationProxyApplication                             Remove-AzureADUserAppRoleAssignment
Get-AzureADContact                                                 New-AzureADApplicationProxyConnectorGroup                          Remove-AzureADUserExtension
Get-AzureADContactDirectReport                                     New-AzureADDevice                                                  Remove-AzureADUserManager
Get-AzureADContactManager                                          New-AzureADDirectorySetting                                        Reset-AzureADMSLifeCycleGroup
Get-AzureADContactMembership                                       New-AzureADDomain                                                  Restore-AzureADDeletedApplication
Get-AzureADContactThumbnailPhoto                                   New-AzureADExternalDomainFederation                                Restore-AzureADMSDeletedDirectoryObject
Get-AzureADContract                                                New-AzureADGroup                                                   Revoke-AzureADSignedInUserAllRefreshToken
Get-AzureADCurrentSessionInfo                                      New-AzureADGroupAppRoleAssignment                                  Revoke-AzureADUserAllRefreshToken
Get-AzureADDeletedApplication                                      New-AzureADMSApplication                                           Select-AzureADGroupIdsContactIsMemberOf
Get-AzureADDevice                                                  New-AzureADMSApplicationExtensionProperty                          Select-AzureADGroupIdsGroupIsMemberOf
Get-AzureADDeviceConfiguration                                     New-AzureADMSApplicationFromApplicationTemplate                    Select-AzureADGroupIdsServicePrincipalIsMemberOf
Get-AzureADDeviceRegisteredOwner                                   New-AzureADMSApplicationKey                                        Select-AzureADGroupIdsUserIsMemberOf
Get-AzureADDeviceRegisteredUser                                    New-AzureADMSApplicationPassword                                   Set-AzureADAdministrativeUnit
Get-AzureADDirectoryRole                                           New-AzureADMSConditionalAccessPolicy                               Set-AzureADApplication
Get-AzureADDirectoryRoleMember                                     New-AzureADMSFeatureRolloutPolicy                                  Set-AzureADApplicationLogo
Get-AzureADDirectoryRoleTemplate                                   New-AzureADMSGroup                                                 Set-AzureADApplicationProxyApplication
Get-AzureADDirectorySetting                                        New-AzureADMSGroupLifecyclePolicy                                  Set-AzureADApplicationProxyApplicationConnectorGroup
Get-AzureADDirectorySettingTemplate                                New-AzureADMSIdentityProvider                                      Set-AzureADApplicationProxyApplicationCustomDomainCertificate
Get-AzureADDomain                                                  New-AzureADMSInvitation                                            Set-AzureADApplicationProxyApplicationSingleSignOn
Get-AzureADDomainNameReference                                     New-AzureADMSNamedLocationPolicy                                   Set-AzureADApplicationProxyConnector
Get-AzureADDomainServiceConfigurationRecord                        New-AzureADMSPasswordSingleSignOnCredential                        Set-AzureADApplicationProxyConnectorGroup
Get-AzureADDomainVerificationDnsRecord                             New-AzureADMSPermissionGrantConditionSet                           Set-AzureADDevice
Get-AzureADExtensionProperty                                       New-AzureADMSPermissionGrantPolicy                                 Set-AzureADDirectorySetting
Get-AzureADExternalDomainFederation                                New-AzureADMSRoleAssignment                                        Set-AzureADDomain
Get-AzureADGroup                                                   New-AzureADMSRoleDefinition                                        Set-AzureADGroup
Get-AzureADGroupAppRoleAssignment                                  New-AzureADMSTrustFrameworkPolicy                                  Set-AzureADMSApplication
Get-AzureADGroupMember                                             New-AzureADObjectSetting                                           Set-AzureADMSApplicationLogo
Get-AzureADGroupOwner                                              New-AzureADPolicy                                                  Set-AzureADMSApplicationVerifiedPublisher
Get-AzureADMSApplication                                           New-AzureADPrivilegedRoleAssignment                                Set-AzureADMSAuthorizationPolicy
Get-AzureADMSApplicationExtensionProperty                          New-AzureADServiceAppRoleAssignment                                Set-AzureADMSConditionalAccessPolicy
Get-AzureADMSApplicationOwner                                      New-AzureADServicePrincipal                                        Set-AzureADMSFeatureRolloutPolicy
Get-AzureADMSApplicationTemplate                                   New-AzureADServicePrincipalKeyCredential                           Set-AzureADMSGroup
Get-AzureADMSAuthorizationPolicy                                   New-AzureADServicePrincipalPasswordCredential                      Set-AzureADMSGroupLifecyclePolicy
Get-AzureADMSConditionalAccessPolicy                               New-AzureADTrustedCertificateAuthority                             Set-AzureADMSIdentityProvider
Get-AzureADMSDeletedDirectoryObject                                New-AzureADUser                                                    Set-AzureADMSNamedLocationPolicy
Get-AzureADMSDeletedGroup                                          New-AzureADUserAppRoleAssignment                                   Set-AzureADMSPasswordSingleSignOnCredential
Get-AzureADMSFeatureRolloutPolicy                                  Open-AzureADMSPrivilegedRoleAssignmentRequest                      Set-AzureADMSPermissionGrantConditionSet
Get-AzureADMSGroup                                                 Remove-AzureADAdministrativeUnit                                   Set-AzureADMSPermissionGrantPolicy
Get-AzureADMSGroupLifecyclePolicy                                  Remove-AzureADAdministrativeUnitMember                             Set-AzureADMSPrivilegedRoleAssignmentRequest
Get-AzureADMSGroupPermissionGrant                                  Remove-AzureADApplication                                          Set-AzureADMSPrivilegedRoleSetting
Get-AzureADMSIdentityProvider                                      Remove-AzureADApplicationExtensionProperty                         Set-AzureADMSRoleDefinition
Get-AzureADMSLifecyclePolicyGroup                                  Remove-AzureADApplicationKeyCredential                             Set-AzureADMSTrustFrameworkPolicy
Get-AzureADMSNamedLocationPolicy                                   Remove-AzureADApplicationOwner                                     Set-AzureADObjectSetting
Get-AzureADMSPasswordSingleSignOnCredential                        Remove-AzureADApplicationPasswordCredential                        Set-AzureADPolicy
Get-AzureADMSPermissionGrantConditionSet                           Remove-AzureADApplicationPolicy                                    Set-AzureADServicePrincipal
Get-AzureADMSPermissionGrantPolicy                                 Remove-AzureADApplicationProxyApplication                          Set-AzureADTenantDetail
Get-AzureADMSPrivilegedResource                                    Remove-AzureADApplicationProxyApplicationConnectorGroup            Set-AzureADTrustedCertificateAuthority
Get-AzureADMSPrivilegedRoleAssignment                              Remove-AzureADApplicationProxyConnectorGroup                       Set-AzureADUser
Get-AzureADMSPrivilegedRoleAssignmentRequest                       Remove-AzureADContact                                              Set-AzureADUserExtension
Get-AzureADMSPrivilegedRoleDefinition                              Remove-AzureADContactManager                                       Set-AzureADUserLicense
Get-AzureADMSPrivilegedRoleSetting                                 Remove-AzureADDeletedApplication                                   Set-AzureADUserManager
Get-AzureADMSRoleAssignment                                        Remove-AzureADDevice                                               Set-AzureADUserPassword
Get-AzureADMSRoleDefinition                                        Remove-AzureADDeviceRegisteredOwner                                Set-AzureADUserThumbnailPhoto
Get-AzureADMSServicePrincipalDelegatedPermissionClassification     Remove-AzureADDeviceRegisteredUser                                 Update-AzureADSignedInUserPassword
Get-AzureADMSTrustFrameworkPolicy                                  Remove-AzureADDirectoryRoleMember
Get-AzureADOAuth2PermissionGrant                                   Remove-AzureADDirectorySetting
PS C:\Program Files\Notepad++> AzureADPreview\Get-AzureADServicePrincipalOAuth2PermissionGrant

cmdlet Get-AzureADServicePrincipalOAuth2PermissionGrant at command pipeline position 1
Supply values for the following parameters:
ObjectId: ([System.Runtime.Serialization.ObjectIDGenerator])
Get-AzureADServicePrincipalOAuth2PermissionGrant: You must call the Connect-AzureAD cmdlet before calling any other cmdlets.
PS C:\Program Files\Notepad++> AzureADPreview\Add-AzureADServicePrincipalPolicy ([System.Runtime.Serialization.ObjectIDGenerator])
Add-AzureADServicePrincipalPolicy: A positional parameter cannot be found that accepts argument 'System.Runtime.Serialization.ObjectIDGenerator'.
PS C:\Program Files\Notepad++> AzureADPreview\Add-AzureADServicePrincipalPolicy :([System.Runtime.Serialization.ObjectIDGenerator])
Add-AzureADServicePrincipalPolicy: A positional parameter cannot be found that accepts argument ':'.
PS C:\Program Files\Notepad++> AzureADPreview\Add-AzureADServicePrincipalPolicy:([System.Runtime.Serialization.ObjectIDGenerator])
AzureADPreview\Add-AzureADServicePrincipalPolicy:: The term 'AzureADPreview\Add-AzureADServicePrincipalPolicy:' is not recognized as a name of a cmdlet, function, script file, or executable program.
Check the spelling of the name, or if a path was included, verify that the path is correct and try again.
PS C:\Program Files\Notepad++> AzureADPreview\Add-AzureADServicePrincipalPolicy ||([System.Runtime.Serialization.ObjectIDGenerator])

cmdlet Add-AzureADServicePrincipalPolicy at command pipeline position 1
Supply values for the following parameters:
Id:
RefObjectId:
Add-AzureADServicePrincipalPolicy: Cannot bind argument to parameter 'Id' because it is an empty string.

IsPublic IsSerial Name                                     BaseType
-------- -------- ----                                     --------
True     False    ObjectIDGenerator                        System.Object

PS C:\Program Files\Notepad++> ([System.Runtime.Serialization.ObjectIDGenerator]).id
PS C:\Program Files\Notepad++> explorer.exe
PS C:\Program Files\Notepad++> ([System.Runtime.Serialization.ObjectIDGenerator]).GUID

Guid
----
0642b586-4018-3dfe-b378-6d7f4137fa15

PS C:\Program Files\Notepad++> AzureADPreview\Add-AzureADServicePrincipalPolicy ||([System.Runtime.Serialization.ObjectIDGenerator])

cmdlet Add-AzureADServicePrincipalPolicy at command pipeline position 1
Supply values for the following parameters:
Id: 0642b586-4018-3dfe-b378-6d7f4137fa15
RefObjectId: 2b586-4018-3dfe-b378-6d7f4137fa15
Add-AzureADServicePrincipalPolicy: You must call the Connect-AzureAD cmdlet before calling any other cmdlets.

IsPublic IsSerial Name                                     BaseType
-------- -------- ----                                     --------
True     False    ObjectIDGenerator                        System.Object

PS C:\Program Files\Notepad++> AzureADPreview\Add-AzureADServicePrincipalPolicy ||([System.Runtime.Serialization.ObjectIDGenerator])

cmdlet Add-AzureADServicePrincipalPolicy at command pipeline position 1
Supply values for the following parameters:
Id: 2b586-4018-3dfe-b378-6d7f4137fa15
RefObjectId: 2b586-4018-3dfe-b378-6d7f4137fa15
Add-AzureADServicePrincipalPolicy: You must call the Connect-AzureAD cmdlet before calling any other cmdlets.

IsPublic IsSerial Name                                     BaseType
-------- -------- ----                                     --------
True     False    ObjectIDGenerator                        System.Object

PS C:\Program Files\Notepad++> AzureADPreview\Add-AzureADServicePrincipalPolicy ||([System.Runtime.Serialization.ObjectIDGenerator]) | Format-Custom

cmdlet Add-AzureADServicePrincipalPolicy at command pipeline position 1
Supply values for the following parameters:
Id: 0642b586-4018-3dfe-b378-6d7f4137fa15
RefObjectId: 0642b586-4018-3dfe-b378-6d7f4137fa15
Add-AzureADServicePrincipalPolicy: You must call the Connect-AzureAD cmdlet before calling any other cmdlets.

class RuntimeType
{
  IsCollectible = False
  DeclaringMethod =
  FullName = System.Runtime.Serialization.ObjectIDGenerator
  AssemblyQualifiedName = System.Runtime.Serialization.ObjectIDGenerator, System.Runtime.Serialization.Formatters, Version=5.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a
  Namespace = System.Runtime.Serialization
  GUID =
    class Guid
    {
      Guid = 0642b586-4018-3dfe-b378-6d7f4137fa15
    }
  GenericParameterAttributes =
  IsSZArray = False
  GenericParameterPosition =
  ContainsGenericParameters = False
  StructLayoutAttribute =
    class StructLayoutAttribute
    {
      Value = Auto
      TypeId =
        class RuntimeType
        {
          IsCollectible = False
          DeclaringMethod =
          FullName = System.Runtime.InteropServices.StructLayoutAttribute
          AssemblyQualifiedName = System.Runtime.InteropServices.StructLayoutAttribute, System.Private.CoreLib, Version=5.0.0.0, Culture=neutral, PublicKeyToken=7cec85d7bea7798e
          Namespace = System.Runtime.InteropServices
          GUID =
            class Guid
            {
              Guid = 3bdab7da-95d9-31ab-b713-4d9d74b610e6
            }
          GenericParameterAttributes =
          IsSZArray = False
          GenericParameterPosition =
          ContainsGenericParameters = False
          StructLayoutAttribute =
            class StructLayoutAttribute
            {
              Value = Auto
              TypeId =
                class RuntimeType
                {
                  IsCollectible = False
                  DeclaringMethod =
                  FullName = System.Runtime.InteropServices.StructLayoutAttribute
                  AssemblyQualifiedName = System.Runtime.InteropServices.StructLayoutAttribute, System.Private.CoreLib, Version=5.0.0.0, Culture=neutral, PublicKeyToken=7cec85d7bea7798e
                  Namespace = System.Runtime.InteropServices
                  GUID =
                    class Guid
                    {
                      Guid = 3bdab7da-95d9-31ab-b713-4d9d74b610e6
                    }
                  GenericParameterAttributes =
                  IsSZArray = False
                  GenericParameterPosition =
                  ContainsGenericParameters = False
                  StructLayoutAttribute =
                    class StructLayoutAttribute
                    {
                      Value = Auto
                      TypeId = System.Runtime.InteropServices.StructLayoutAttribute
                      Pack = 8
                      Size = 0
                      CharSet = Ansi
                    }
                  Name = StructLayoutAttribute
                  DeclaringType =
                  Assembly =
                    class RuntimeAssembly
                    {
                      CodeBase = file:///C:/Program Files/dotnet/shared/Microsoft.NETCore.App/5.0.3/System.Private.CoreLib.dll
                      FullName = System.Private.CoreLib, Version=5.0.0.0, Culture=neutral, PublicKeyToken=7cec85d7bea7798e
                      EntryPoint =
                      DefinedTypes =
                        [
                          Microsoft.CodeAnalysis.EmbeddedAttribute
                          System.Runtime.CompilerServices.IsUnmanagedAttribute
                          System.Runtime.CompilerServices.NullableAttribute
                          System.Runtime.CompilerServices.NullableContextAttribute
                          …
                        ]

                      IsCollectible = False
                      ManifestModule = System.Private.CoreLib.dll
                      ReflectionOnly = False
                      Location = C:\Program Files\dotnet\shared\Microsoft.NETCore.App\5.0.3\System.Private.CoreLib.dll
                      ImageRuntimeVersion = v4.0.30319
                      GlobalAssemblyCache = False
                      HostContext = 0
                      IsDynamic = False
                      ExportedTypes =
                        [
                          Microsoft.Win32.SafeHandles.CriticalHandleMinusOneIsInvalid
                          Microsoft.Win32.SafeHandles.CriticalHandleZeroOrMinusOneIsInvalid
                          Microsoft.Win32.SafeHandles.SafeHandleMinusOneIsInvalid
                          Microsoft.Win32.SafeHandles.SafeHandleZeroOrMinusOneIsInvalid
                          …
                        ]

                      IsFullyTrusted = True
                      CustomAttributes =
                        [
                          [System.Reflection.AssemblyProductAttribute("Microsoft® .NET")]
                          [System.Runtime.CompilerServices.CompilationRelaxationsAttribute((Int32)8)]
                          [System.Runtime.CompilerServices.RuntimeCompatibilityAttribute(WrapNonExceptionThrows = True)]
                          [System.Diagnostics.DebuggableAttribute((System.Diagnostics.DebuggableAttribute+DebuggingModes)2)]
                          …
                        ]

                      EscapedCodeBase = file:///C:/Program%20Files/dotnet/shared/Microsoft.NETCore.App/5.0.3/System.Private.CoreLib.dll
                      Modules =
                        [
                          System.Private.CoreLib.dll
                        ]

                      SecurityRuleSet = None
                    }
                  BaseType =
                    class RuntimeType
                    {
                      IsCollectible = False
                      DeclaringMethod =
                      FullName = System.Attribute
                      AssemblyQualifiedName = System.Attribute, System.Private.CoreLib, Version=5.0.0.0, Culture=neutral, PublicKeyToken=7cec85d7bea7798e
                      Namespace = System
                      GUID = ff3e96d8-3d3c-32b8-a071-931a69bbfbb3
                      GenericParameterAttributes =
                      IsSZArray = False
                      GenericParameterPosition =
                      ContainsGenericParameters = False
                      StructLayoutAttribute = System.Runtime.InteropServices.StructLayoutAttribute
                      Name = Attribute
                      DeclaringType =
                      Assembly = System.Private.CoreLib, Version=5.0.0.0, Culture=neutral, PublicKeyToken=7cec85d7bea7798e
                      BaseType = System.Object
                      IsByRefLike = False
                      IsConstructedGenericType = False
                      IsGenericType = False
                      IsGenericTypeDefinition = False
                      IsGenericParameter = False
                      IsTypeDefinition = True
                      IsSecurityCritical = True
                      IsSecuritySafeCritical = False
                      IsSecurityTransparent = False
                      MemberType = TypeInfo
                      MetadataToken = 33554517
                      Module = System.Private.CoreLib.dll
                      ReflectedType =
                      TypeHandle = System.RuntimeTypeHandle
                      UnderlyingSystemType = System.Attribute
                      GenericTypeParameters =
                        [
                        ]

                      DeclaredConstructors =
                        [
                          Void .ctor()
                        ]

                      DeclaredEvents =
                        [
                        ]

                      DeclaredFields =
                        [
                        ]

                      DeclaredMembers =
                        [
                          System.Attribute[] InternalGetCustomAttributes(System.Reflection.PropertyInfo, System.Type, Boolean)
                          Boolean InternalIsDefined(System.Reflection.PropertyInfo, System.Type, Boolean)
                          System.Reflection.PropertyInfo GetParentDefinition(System.Reflection.PropertyInfo, System.Type[])
                          System.Attribute[] InternalGetCustomAttributes(System.Reflection.EventInfo, System.Type, Boolean)
                          …
                        ]

                      DeclaredMethods =
                        [
                          System.Attribute[] InternalGetCustomAttributes(System.Reflection.PropertyInfo, System.Type, Boolean)
                          Boolean InternalIsDefined(System.Reflection.PropertyInfo, System.Type, Boolean)
                          System.Reflection.PropertyInfo GetParentDefinition(System.Reflection.PropertyInfo, System.Type[])
                          System.Attribute[] InternalGetCustomAttributes(System.Reflection.EventInfo, System.Type, Boolean)
                          …
                        ]

                      DeclaredNestedTypes =
                        [
                        ]

                      DeclaredProperties =
                        [
                          System.Object TypeId
                        ]

                      ImplementedInterfaces =
                        [
                        ]

                      IsInterface = False
                      IsNested = False
                      IsArray = False
                      IsByRef = False
                      IsPointer = False
                      IsGenericTypeParameter = False
                      IsGenericMethodParameter = False
                      IsVariableBoundArray = False
                      HasElementType = False
                      GenericTypeArguments =
                        [
                        ]

                      Attributes = AutoLayout, AnsiClass, Class, Public, Abstract, Serializable, BeforeFieldInit
                      IsAbstract = True
                      IsImport = False
                      IsSealed = False
                      IsSpecialName = False
                      IsClass = True
                      IsNestedAssembly = False
                      IsNestedFamANDAssem = False
                      IsNestedFamily = False
                      IsNestedFamORAssem = False
                      IsNestedPrivate = False
                      IsNestedPublic = False
                      IsNotPublic = False
                      IsPublic = True
                      IsAutoLayout = True
                      IsExplicitLayout = False
                      IsLayoutSequential = False
                      IsAnsiClass = True
                      IsAutoClass = False
                      IsUnicodeClass = False
                      IsCOMObject = False
                      IsContextful = False
                      IsEnum = False
                      IsMarshalByRef = False
                      IsPrimitive = False
                      IsValueType = False
                      IsSignatureType = False
                      TypeInitializer =
                      IsSerializable = True
                      IsVisible = True
                      CustomAttributes =
                        [
                          [System.SerializableAttribute()]
                          [System.Runtime.CompilerServices.NullableContextAttribute((Byte)1)]
                          [System.Runtime.CompilerServices.NullableAttribute((Byte)0)]
                          [System.AttributeUsageAttribute((System.AttributeTargets)32767, AllowMultiple = False, Inherited = True)]
                          …
                        ]

                    }
                  IsByRefLike = False
                  IsConstructedGenericType = False
                  IsGenericType = False
                  IsGenericTypeDefinition = False
                  IsGenericParameter = False
                  IsTypeDefinition = True
                  IsSecurityCritical = True
                  IsSecuritySafeCritical = False
                  IsSecurityTransparent = False
                  MemberType = TypeInfo
                  MetadataToken = 33555616
                  Module =
                    class RuntimeModule
                    {
                      MDStreamVersion = 131072
                      FullyQualifiedName = C:\Program Files\dotnet\shared\Microsoft.NETCore.App\5.0.3\System.Private.CoreLib.dll
                      ModuleVersionId = 3bb42fd3-8bd8-407b-9667-fbf8ce1367e9
                      MetadataToken = 1
                      ScopeName = System.Private.CoreLib.dll
                      Name = System.Private.CoreLib.dll
                      Assembly = System.Private.CoreLib, Version=5.0.0.0, Culture=neutral, PublicKeyToken=7cec85d7bea7798e
                      ModuleHandle = System.ModuleHandle
                      CustomAttributes =
                        [
                          [System.Runtime.CompilerServices.NullablePublicOnlyAttribute((Boolean)False)]
                          [System.Runtime.CompilerServices.SkipLocalsInitAttribute()]
                        ]

                    }
                  ReflectedType =
                  TypeHandle =
                    class RuntimeTypeHandle
                    {
                      Value = 140720542434808
                    }
                  UnderlyingSystemType =
                    class RuntimeType
                    {
                      IsCollectible = False
                      DeclaringMethod =
                      FullName = System.Runtime.InteropServices.StructLayoutAttribute
                      AssemblyQualifiedName = System.Runtime.InteropServices.StructLayoutAttribute, System.Private.CoreLib, Version=5.0.0.0, Culture=neutral, PublicKeyToken=7cec85d7bea7798e
                      Namespace = System.Runtime.InteropServices
                      GUID = 3bdab7da-95d9-31ab-b713-4d9d74b610e6
                      GenericParameterAttributes =
                      IsSZArray = False
                      GenericParameterPosition =
                      ContainsGenericParameters = False
                      StructLayoutAttribute = System.Runtime.InteropServices.StructLayoutAttribute
                      Name = StructLayoutAttribute
                      DeclaringType =
                      Assembly = System.Private.CoreLib, Version=5.0.0.0, Culture=neutral, PublicKeyToken=7cec85d7bea7798e
                      BaseType = System.Attribute
                      IsByRefLike = False
                      IsConstructedGenericType = False
                      IsGenericType = False
                      IsGenericTypeDefinition = False
                      IsGenericParameter = False
                      IsTypeDefinition = True
                      IsSecurityCritical = True
                      IsSecuritySafeCritical = False
                      IsSecurityTransparent = False
                      MemberType = TypeInfo
                      MetadataToken = 33555616
                      Module = System.Private.CoreLib.dll
                      ReflectedType =
                      TypeHandle = System.RuntimeTypeHandle
                      UnderlyingSystemType = System.Runtime.InteropServices.StructLayoutAttribute
                      GenericTypeParameters =
                        [
                        ]

                      DeclaredConstructors =
                        [
                          Void .ctor(System.Runtime.InteropServices.LayoutKind)
                          Void .ctor(Int16)
                        ]

                      DeclaredEvents =
                        [
                        ]

                      DeclaredFields =
                        [
                          System.Runtime.InteropServices.LayoutKind <Value>k__BackingField
                          Int32 Pack
                          Int32 Size
                          System.Runtime.InteropServices.CharSet CharSet
                        ]

                      DeclaredMembers =
                        [
                          System.Runtime.InteropServices.LayoutKind get_Value()
                          Void .ctor(System.Runtime.InteropServices.LayoutKind)
                          Void .ctor(Int16)
                          System.Runtime.InteropServices.LayoutKind Value
                          …
                        ]

                      DeclaredMethods =
                        [
                          System.Runtime.InteropServices.LayoutKind get_Value()
                        ]

                      DeclaredNestedTypes =
                        [
                        ]

                      DeclaredProperties =
                        [
                          System.Runtime.InteropServices.LayoutKind Value
                        ]

                      ImplementedInterfaces =
                        [
                        ]

                      IsInterface = False
                      IsNested = False
                      IsArray = False
                      IsByRef = False
                      IsPointer = False
                      IsGenericTypeParameter = False
                      IsGenericMethodParameter = False
                      IsVariableBoundArray = False
                      HasElementType = False
                      GenericTypeArguments =
                        [
                        ]

                      Attributes = AutoLayout, AnsiClass, Class, Public, Sealed, BeforeFieldInit
                      IsAbstract = False
                      IsImport = False
                      IsSealed = True
                      IsSpecialName = False
                      IsClass = True
                      IsNestedAssembly = False
                      IsNestedFamANDAssem = False
                      IsNestedFamily = False
                      IsNestedFamORAssem = False
                      IsNestedPrivate = False
                      IsNestedPublic = False
                      IsNotPublic = False
                      IsPublic = True
                      IsAutoLayout = True
                      IsExplicitLayout = False
                      IsLayoutSequential = False
                      IsAnsiClass = True
                      IsAutoClass = False
                      IsUnicodeClass = False
                      IsCOMObject = False
                      IsContextful = False
                      IsEnum = False
                      IsMarshalByRef = False
                      IsPrimitive = False
                      IsValueType = False
                      IsSignatureType = False
                      TypeInitializer =
                      IsSerializable = False
                      IsVisible = True
                      CustomAttributes =
                        [
                          [System.AttributeUsageAttribute((System.AttributeTargets)12, Inherited = False)]
                        ]

                    }
                  GenericTypeParameters =
                    [
                    ]

                  DeclaredConstructors =
                    [
                      Void .ctor(System.Runtime.InteropServices.LayoutKind)
                      Void .ctor(Int16)
                    ]

                  DeclaredEvents =
                    [
                    ]

                  DeclaredFields =
                    [
                      System.Runtime.InteropServices.LayoutKind <Value>k__BackingField
                      Int32 Pack
                      Int32 Size
                      System.Runtime.InteropServices.CharSet CharSet
                    ]

                  DeclaredMembers =
                    [
                      System.Runtime.InteropServices.LayoutKind get_Value()
                      Void .ctor(System.Runtime.InteropServices.LayoutKind)
                      Void .ctor(Int16)
                      System.Runtime.InteropServices.LayoutKind Value
                      …
                    ]

                  DeclaredMethods =
                    [
                      System.Runtime.InteropServices.LayoutKind get_Value()
                    ]

                  DeclaredNestedTypes =
                    [
                    ]

                  DeclaredProperties =
                    [
                      System.Runtime.InteropServices.LayoutKind Value
                    ]

                  ImplementedInterfaces =
                    [
                    ]

                  IsInterface = False
                  IsNested = False
                  IsArray = False
                  IsByRef = False
                  IsPointer = False
                  IsGenericTypeParameter = False
                  IsGenericMethodParameter = False
                  IsVariableBoundArray = False
                  HasElementType = False
                  GenericTypeArguments =
                    [
                    ]

                  Attributes = AutoLayout, AnsiClass, Class, Public, Sealed, BeforeFieldInit
                  IsAbstract = False
                  IsImport = False
                  IsSealed = True
                  IsSpecialName = False
                  IsClass = True
                  IsNestedAssembly = False
                  IsNestedFamANDAssem = False
                  IsNestedFamily = False
                  IsNestedFamORAssem = False
                  IsNestedPrivate = False
                  IsNestedPublic = False
                  IsNotPublic = False
                  IsPublic = True
                  IsAutoLayout = True
                  IsExplicitLayout = False
                  IsLayoutSequential = False
                  IsAnsiClass = True
                  IsAutoClass = False
                  IsUnicodeClass = False
                  IsCOMObject = False
                  IsContextful = False
                  IsEnum = False
                  IsMarshalByRef = False
                  IsPrimitive = False
                  IsValueType = False
                  IsSignatureType = False
                  TypeInitializer =
                  IsSerializable = False
                  IsVisible = True
                  CustomAttributes =
                    [
                      [System.AttributeUsageAttribute((System.AttributeTargets)12, Inherited = False)]
                    ]

                }
              Pack = 8
              Size = 0
              CharSet = Ansi
            }
          Name = StructLayoutAttribute
          DeclaringType =
          Assembly =
            class RuntimeAssembly
            {
              CodeBase = file:///C:/Program Files/dotnet/shared/Microsoft.NETCore.App/5.0.3/System.Private.CoreLib.dll
              FullName = System.Private.CoreLib, Version=5.0.0.0, Culture=neutral, PublicKeyToken=7cec85d7bea7798e
              EntryPoint =
              DefinedTypes =
                [
                  class RuntimeType
                  {
                    IsCollectible = False
                    DeclaringMethod =
                    FullName = Microsoft.CodeAnalysis.EmbeddedAttribute
                    AssemblyQualifiedName = Microsoft.CodeAnalysis.EmbeddedAttribute, System.Private.CoreLib, Version=5.0.0.0, Culture=neutral, PublicKeyToken=7cec85d7bea7798e
                    Namespace = Microsoft.CodeAnalysis
                    GUID = d2a432de-b8a1-32f1-b2d9-b293ef7046c0
                    GenericParameterAttributes =
                    IsSZArray = False
                    GenericParameterPosition =
                    ContainsGenericParameters = False
                    StructLayoutAttribute = System.Runtime.InteropServices.StructLayoutAttribute
                    Name = EmbeddedAttribute
                    DeclaringType =
                    Assembly = System.Private.CoreLib, Version=5.0.0.0, Culture=neutral, PublicKeyToken=7cec85d7bea7798e
                    BaseType = System.Attribute
                    IsByRefLike = False
                    IsConstructedGenericType = False
                    IsGenericType = False
                    IsGenericTypeDefinition = False
                    IsGenericParameter = False
                    IsTypeDefinition = True
                    IsSecurityCritical = True
                    IsSecuritySafeCritical = False
                    IsSecurityTransparent = False
                    MemberType = TypeInfo
                    MetadataToken = 33554434
                    Module = System.Private.CoreLib.dll
                    ReflectedType =
                    TypeHandle = System.RuntimeTypeHandle
                    UnderlyingSystemType = Microsoft.CodeAnalysis.EmbeddedAttribute
                    GenericTypeParameters =
                      [
                      ]

                    DeclaredConstructors =
                      [
                        Void .ctor()
                      ]

                    DeclaredEvents =
                      [
                      ]

                    DeclaredFields =
                      [
                      ]

                    DeclaredMembers =
                      [
                        Void .ctor()
                      ]

                    DeclaredMethods =
                      [
                      ]

                    DeclaredNestedTypes =
                      [
                      ]

                    DeclaredProperties =
                      [
                      ]

                    ImplementedInterfaces =
                      [
                      ]

                    IsInterface = False
                    IsNested = False
                    IsArray = False
                    IsByRef = False
                    IsPointer = False
                    IsGenericTypeParameter = False
                    IsGenericMethodParameter = False
                    IsVariableBoundArray = False
                    HasElementType = False
                    GenericTypeArguments =
                      [
                      ]

                    Attributes = AutoLayout, AnsiClass, Class, Sealed, BeforeFieldInit
                    IsAbstract = False
                    IsImport = False
                    IsSealed = True
                    IsSpecialName = False
                    IsClass = True
                    IsNestedAssembly = False
                    IsNestedFamANDAssem = False
                    IsNestedFamily = False
                    IsNestedFamORAssem = False
                    IsNestedPrivate = False
                    IsNestedPublic = False
                    IsNotPublic = True
                    IsPublic = False
                    IsAutoLayout = True
                    IsExplicitLayout = False
                    IsLayoutSequential = False
                    IsAnsiClass = True
                    IsAutoClass = False
                    IsUnicodeClass = False
                    IsCOMObject = False
                    IsContextful = False
                    IsEnum = False
                    IsMarshalByRef = False
                    IsPrimitive = False
                    IsValueType = False
                    IsSignatureType = False
                    TypeInitializer =
                    IsSerializable = False
                    IsVisible = False
                    CustomAttributes =
                      [
                        [System.Runtime.CompilerServices.CompilerGeneratedAttribute()]
                        [Microsoft.CodeAnalysis.EmbeddedAttribute()]
                      ]

                  }
                  class RuntimeType
                  {
                    IsCollectible = False
                    DeclaringMethod =
                    FullName = System.Runtime.CompilerServices.IsUnmanagedAttribute
                    AssemblyQualifiedName = System.Runtime.CompilerServices.IsUnmanagedAttribute, System.Private.CoreLib, Version=5.0.0.0, Culture=neutral, PublicKeyToken=7cec85d7bea7798e
                    Namespace = System.Runtime.CompilerServices
                    GUID = ed0dd017-120e-365a-be7e-819028670f6f
                    GenericParameterAttributes =
                    IsSZArray = False
                    GenericParameterPosition =
                    ContainsGenericParameters = False
                    StructLayoutAttribute = System.Runtime.InteropServices.StructLayoutAttribute
                    Name = IsUnmanagedAttribute
                    DeclaringType =
                    Assembly = System.Private.CoreLib, Version=5.0.0.0, Culture=neutral, PublicKeyToken=7cec85d7bea7798e
                    BaseType = System.Attribute
                    IsByRefLike = False
                    IsConstructedGenericType = False
                    IsGenericType = False
                    IsGenericTypeDefinition = False
                    IsGenericParameter = False
                    IsTypeDefinition = True
                    IsSecurityCritical = True
                    IsSecuritySafeCritical = False
                    IsSecurityTransparent = False
                    MemberType = TypeInfo
                    MetadataToken = 33554435
                    Module = System.Private.CoreLib.dll
                    ReflectedType =
                    TypeHandle = System.RuntimeTypeHandle
                    UnderlyingSystemType = System.Runtime.CompilerServices.IsUnmanagedAttribute
                    GenericTypeParameters =
                      [
                      ]

                    DeclaredConstructors =
                      [
                        Void .ctor()
                      ]

                    DeclaredEvents =
                      [
                      ]

                    DeclaredFields =
                      [
                      ]

                    DeclaredMembers =
                      [
                        Void .ctor()
                      ]

                    DeclaredMethods =
                      [
                      ]

                    DeclaredNestedTypes =
                      [
                      ]

                    DeclaredProperties =
                      [
                      ]

                    ImplementedInterfaces =
                      [
                      ]

                    IsInterface = False
                    IsNested = False
                    IsArray = False
                    IsByRef = False
                    IsPointer = False
                    IsGenericTypeParameter = False
                    IsGenericMethodParameter = False
                    IsVariableBoundArray = False
                    HasElementType = False
                    GenericTypeArguments =
                      [
                      ]

                    Attributes = AutoLayout, AnsiClass, Class, Sealed, BeforeFieldInit
                    IsAbstract = False
                    IsImport = False
                    IsSealed = True
                    IsSpecialName = False
                    IsClass = True
                    IsNestedAssembly = False
                    IsNestedFamANDAssem = False
                    IsNestedFamily = False
                    IsNestedFamORAssem = False
                    IsNestedPrivate = False
                    IsNestedPublic = False
                    IsNotPublic = True
                    IsPublic = False
                    IsAutoLayout = True
                    IsExplicitLayout = False
                    IsLayoutSequential = False
                    IsAnsiClass = True
                    IsAutoClass = False
                    IsUnicodeClass = False
                    IsCOMObject = False
                    IsContextful = False
                    IsEnum = False
                    IsMarshalByRef = False
                    IsPrimitive = False
                    IsValueType = False
                    IsSignatureType = False
                    TypeInitializer =
                    IsSerializable = False
                    IsVisible = False
                    CustomAttributes =
                      [
                        [System.Runtime.CompilerServices.CompilerGeneratedAttribute()]
                        [Microsoft.CodeAnalysis.EmbeddedAttribute()]
                      ]

                  }
                  class RuntimeType
                  {
                    IsCollectible = False
                    DeclaringMethod =
                    FullName = System.Runtime.CompilerServices.NullableAttribute
                    AssemblyQualifiedName = System.Runtime.CompilerServices.NullableAttribute, System.Private.CoreLib, Version=5.0.0.0, Culture=neutral, PublicKeyToken=7cec85d7bea7798e
                    Namespace = System.Runtime.CompilerServices
                    GUID = 9badf206-d632-3fdb-8b2a-b2fd879dedb2
                    GenericParameterAttributes =
                    IsSZArray = False
                    GenericParameterPosition =
                    ContainsGenericParameters = False
                    StructLayoutAttribute = System.Runtime.InteropServices.StructLayoutAttribute
                    Name = NullableAttribute
                    DeclaringType =
                    Assembly = System.Private.CoreLib, Version=5.0.0.0, Culture=neutral, PublicKeyToken=7cec85d7bea7798e
                    BaseType = System.Attribute
                    IsByRefLike = False
                    IsConstructedGenericType = False
                    IsGenericType = False
                    IsGenericTypeDefinition = False
                    IsGenericParameter = False
                    IsTypeDefinition = True
                    IsSecurityCritical = True
                    IsSecuritySafeCritical = False
                    IsSecurityTransparent = False
                    MemberType = TypeInfo
                    MetadataToken = 33554436
                    Module = System.Private.CoreLib.dll
                    ReflectedType =
                    TypeHandle = System.RuntimeTypeHandle
                    UnderlyingSystemType = System.Runtime.CompilerServices.NullableAttribute
                    GenericTypeParameters =
                      [
                      ]

                    DeclaredConstructors =
                      [
                        Void .ctor(Byte)
                        Void .ctor(Byte[])
                      ]

                    DeclaredEvents =
                      [
                      ]

                    DeclaredFields =
                      [
                        Byte[] NullableFlags
                      ]

                    DeclaredMembers =
                      [
                        Void .ctor(Byte)
                        Void .ctor(Byte[])
                        Byte[] NullableFlags
                      ]

                    DeclaredMethods =
                      [
                      ]

                    DeclaredNestedTypes =
                      [
                      ]

                    DeclaredProperties =
                      [
                      ]

                    ImplementedInterfaces =
                      [
                      ]

                    IsInterface = False
                    IsNested = False
                    IsArray = False
                    IsByRef = False
                    IsPointer = False
                    IsGenericTypeParameter = False
                    IsGenericMethodParameter = False
                    IsVariableBoundArray = False
                    HasElementType = False
                    GenericTypeArguments =
                      [
                      ]

                    Attributes = AutoLayout, AnsiClass, Class, Sealed, BeforeFieldInit
                    IsAbstract = False
                    IsImport = False
                    IsSealed = True
                    IsSpecialName = False
                    IsClass = True
                    IsNestedAssembly = False
                    IsNestedFamANDAssem = False
                    IsNestedFamily = False
                    IsNestedFamORAssem = False
                    IsNestedPrivate = False
                    IsNestedPublic = False
                    IsNotPublic = True
                    IsPublic = False
                    IsAutoLayout = True
                    IsExplicitLayout = False
                    IsLayoutSequential = False
                    IsAnsiClass = True
                    IsAutoClass = False
                    IsUnicodeClass = False
                    IsCOMObject = False
                    IsContextful = False
                    IsEnum = False
                    IsMarshalByRef = False
                    IsPrimitive = False
                    IsValueType = False
                    IsSignatureType = False
                    TypeInitializer =
                    IsSerializable = False
                    IsVisible = False
                    CustomAttributes =
                      [
                        [System.Runtime.CompilerServices.CompilerGeneratedAttribute()]
                        [Microsoft.CodeAnalysis.EmbeddedAttribute()]
                        [System.AttributeUsageAttribute((System.AttributeTargets)27524, AllowMultiple = False, Inherited = False)]
                      ]

                  }
                  class RuntimeType
                  {
                    IsCollectible = False
                    DeclaringMethod =
                    FullName = System.Runtime.CompilerServices.NullableContextAttribute
                    AssemblyQualifiedName = System.Runtime.CompilerServices.NullableContextAttribute, System.Private.CoreLib, Version=5.0.0.0, Culture=neutral, PublicKeyToken=7cec85d7bea7798e
                    Namespace = System.Runtime.CompilerServices
                    GUID = 2366016f-0f6c-3270-b2e2-d80ef8afea2f
                    GenericParameterAttributes =
                    IsSZArray = False
                    GenericParameterPosition =
                    ContainsGenericParameters = False
                    StructLayoutAttribute = System.Runtime.InteropServices.StructLayoutAttribute
                    Name = NullableContextAttribute
                    DeclaringType =
                    Assembly = System.Private.CoreLib, Version=5.0.0.0, Culture=neutral, PublicKeyToken=7cec85d7bea7798e
                    BaseType = System.Attribute
                    IsByRefLike = False
                    IsConstructedGenericType = False
                    IsGenericType = False
                    IsGenericTypeDefinition = False
                    IsGenericParameter = False
                    IsTypeDefinition = True
                    IsSecurityCritical = True
                    IsSecuritySafeCritical = False
                    IsSecurityTransparent = False
                    MemberType = TypeInfo
                    MetadataToken = 33554437
                    Module = System.Private.CoreLib.dll
                    ReflectedType =
                    TypeHandle = System.RuntimeTypeHandle
                    UnderlyingSystemType = System.Runtime.CompilerServices.NullableContextAttribute
                    GenericTypeParameters =
                      [
                      ]

                    DeclaredConstructors =
                      [
                        Void .ctor(Byte)
                      ]

                    DeclaredEvents =
                      [
                      ]

                    DeclaredFields =
                      [
                        Byte Flag
                      ]

                    DeclaredMembers =
                      [
                        Void .ctor(Byte)
                        Byte Flag
                      ]

                    DeclaredMethods =
                      [
                      ]

                    DeclaredNestedTypes =
                      [
                      ]

                    DeclaredProperties =
                      [
                      ]

                    ImplementedInterfaces =
                      [
                      ]

                    IsInterface = False
                    IsNested = False
                    IsArray = False
                    IsByRef = False
                    IsPointer = False
                    IsGenericTypeParameter = False
                    IsGenericMethodParameter = False
                    IsVariableBoundArray = False
                    HasElementType = False
                    GenericTypeArguments =
                      [
                      ]

                    Attributes = AutoLayout, AnsiClass, Class, Sealed, BeforeFieldInit
                    IsAbstract = False
                    IsImport = False
                    IsSealed = True
                    IsSpecialName = False
                    IsClass = True
                    IsNestedAssembly = False
                    IsNestedFamANDAssem = False
                    IsNestedFamily = False
                    IsNestedFamORAssem = False
                    IsNestedPrivate = False
                    IsNestedPublic = False
                    IsNotPublic = True
                    IsPublic = False
                    IsAutoLayout = True
                    IsExplicitLayout = False
                    IsLayoutSequential = False
                    IsAnsiClass = True
                    IsAutoClass = False
                    IsUnicodeClass = False
                    IsCOMObject = False
                    IsContextful = False
                    IsEnum = False
                    IsMarshalByRef = False
                    IsPrimitive = False
                    IsValueType = False
                    IsSignatureType = False
                    TypeInitializer =
                    IsSerializable = False
                    IsVisible = False
                    CustomAttributes =
                      [
                        [System.Runtime.CompilerServices.CompilerGeneratedAttribute()]
                        [Microsoft.CodeAnalysis.EmbeddedAttribute()]
                        [System.AttributeUsageAttribute((System.AttributeTargets)5196, AllowMultiple = False, Inherited = False)]
                      ]

                  }
                  …
                ]

              IsCollectible = False
              ManifestModule =
                class RuntimeModule
                {
                  MDStreamVersion = 131072
                  FullyQualifiedName = C:\Program Files\dotnet\shared\Microsoft.NETCore.App\5.0.3\System.Private.CoreLib.dll
                  ModuleVersionId =
                    class Guid
                    {
                      Guid = 3bb42fd3-8bd8-407b-9667-fbf8ce1367e9
                    }
                  MetadataToken = 1
                  ScopeName = System.Private.CoreLib.dll
                  Name = System.Private.CoreLib.dll
                  Assembly =
                    class RuntimeAssembly
                    {
                      CodeBase = file:///C:/Program Files/dotnet/shared/Microsoft.NETCore.App/5.0.3/System.Private.CoreLib.dll
                      FullName = System.Private.CoreLib, Version=5.0.0.0, Culture=neutral, PublicKeyToken=7cec85d7bea7798e
                      EntryPoint =
                      DefinedTypes =
                        [
                          Microsoft.CodeAnalysis.EmbeddedAttribute
                          System.Runtime.CompilerServices.IsUnmanagedAttribute
                          System.Runtime.CompilerServices.NullableAttribute
                          System.Runtime.CompilerServices.NullableContextAttribute
                          …
                        ]

                      IsCollectible = False
                      ManifestModule = System.Private.CoreLib.dll
                      ReflectionOnly = False
                      Location = C:\Program Files\dotnet\shared\Microsoft.NETCore.App\5.0.3\System.Private.CoreLib.dll
                      ImageRuntimeVersion = v4.0.30319
                      GlobalAssemblyCache = False
                      HostContext = 0
                      IsDynamic = False
                      ExportedTypes =
                        [
                          Microsoft.Win32.SafeHandles.CriticalHandleMinusOneIsInvalid
                          Microsoft.Win32.SafeHandles.CriticalHandleZeroOrMinusOneIsInvalid
                          Microsoft.Win32.SafeHandles.SafeHandleMinusOneIsInvalid
                          Microsoft.Win32.SafeHandles.SafeHandleZeroOrMinusOneIsInvalid
                          …
                        ]

                      IsFullyTrusted = True
                      CustomAttributes =
                        [
                          [System.Reflection.AssemblyProductAttribute("Microsoft® .NET")]
                          [System.Runtime.CompilerServices.CompilationRelaxationsAttribute((Int32)8)]
                          [System.Runtime.CompilerServices.RuntimeCompatibilityAttribute(WrapNonExceptionThrows = True)]
                          [System.Diagnostics.DebuggableAttribute((System.Diagnostics.DebuggableAttribute+DebuggingModes)2)]
                          …
                        ]

                      EscapedCodeBase = file:///C:/Program%20Files/dotnet/shared/Microsoft.NETCore.App/5.0.3/System.Private.CoreLib.dll
                      Modules =
                        [
                          System.Private.CoreLib.dll
                        ]

                      SecurityRuleSet = None
                    }
                  ModuleHandle =
PS C:\Program Files\Notepad++> AzureADPreview\Add-AzureADServicePrincipalPolicy ||([System.Runtime.Serialization.ObjectIDGenerator])

cmdlet Add-AzureADServicePrincipalPolicy at command pipeline position 1
Supply values for the following parameters:
Id: 0642b586-4018-3dfe-b378-6d7f4137fa15
RefObjectId: System.Core
Add-AzureADServicePrincipalPolicy: You must call the Connect-AzureAD cmdlet before calling any other cmdlets.

IsPublic IsSerial Name                                     BaseType
-------- -------- ----                                     --------
True     False    ObjectIDGenerator                        System.Object

PS C:\Program Files\Notepad++> AzureADPreview\Add-AzureADServicePrincipalPolicy ||([System.Runtime.Serialization.ObjectIDGenerator])

cmdlet Add-AzureADServicePrincipalPolicy at command pipeline position 1
Supply values for the following parameters:
Id: BigInt
RefObjectId: ServiceDeploymentHash
Add-AzureADServicePrincipalPolicy: You must call the Connect-AzureAD cmdlet before calling any other cmdlets.

IsPublic IsSerial Name                                     BaseType
-------- -------- ----                                     --------
True     False    ObjectIDGenerator                        System.Object

PS C:\Program Files\Notepad++> AzureADPreview\Add-AzureADServicePrincipalPolicy |([System.Runtime.Serialization.ObjectIDGenerator])
ParserError:
Line |
   1 |  … cePrincipalPolicy |([System.Runtime.Serialization.ObjectIDGenerator])
     |                       ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
     | Expressions are only allowed as the first element of a pipeline.

PS C:\Program Files\Notepad++> AzureADPreview\Add-AzureADMSServicePrincipalDelegatedPermissionClassification([System.Runtime.Serialization.ObjectIDGenerator])
Add-AzureADMSServicePrincipalDelegatedPermissionClassification: A positional parameter cannot be found that accepts argument 'System.Runtime.Serialization.ObjectIDGenerator'.
PS C:\Program Files\Notepad++> AzureADPreview\Add-AzureADMSServicePrincipalDelegatedPermissionClassification -PermissionName:.\autoCompletion\

cmdlet Add-AzureADMSServicePrincipalDelegatedPermissionClassification at command pipeline position 1
Supply values for the following parameters:
ServicePrincipalId: bignit
Classification: not null
PermissionId: N,U
Add-AzureADMSServicePrincipalDelegatedPermissionClassification: Cannot bind parameter 'Classification'. Cannot convert value "not null" to type "Microsoft.Open.MSGraph.Model.DelegatedPermissionClassification+ClassificationEnum". Error: "Unable to match the identifier name not null to a valid enumerator name. Specify one of the following enumerator names and try again:
Low, Medium, High"
PS C:\Program Files\Notepad++> AzureADPreview\Add-AzureADMSServicePrincipalDelegatedPermissionClassification -PermissionName:.\autoCompletion\

cmdlet Add-AzureADMSServicePrincipalDelegatedPermissionClassification at command pipeline position 1
Supply values for the following parameters:
ServicePrincipalId: bignit
Classification: low
PermissionId: N,U
Add-AzureADMSServicePrincipalDelegatedPermissionClassification: You must call the Connect-AzureAD cmdlet before calling any other cmdlets.
PS C:\Program Files\Notepad++> Add-AzureADMSApplicationOwner || AzureADPreview\Add-AzureADMSServicePrincipalDelegatedPermissionClassification -PermissionName:.\autoCompletion\ -ServicePrincipalId:bigint -Classification:Low -PermissionId:'N,U'

cmdlet Add-AzureADMSApplicationOwner at command pipeline position 1
Supply values for the following parameters:
ObjectId:
RefObjectId:
Add-AzureADMSApplicationOwner: Cannot bind argument to parameter 'ObjectId' because it is an empty string.
Add-AzureADMSServicePrincipalDelegatedPermissionClassification: You must call the Connect-AzureAD cmdlet before calling any other cmdlets.
PS C:\Program Files\Notepad++>
PS C:\Program Files\Notepad++> Connect-AzureAD || Add-AzureADMSApplicationOwner || AzureADPreview\Add-AzureADMSServicePrincipalDelegatedPermissionClassification -PermissionName:.\autoCompletion\ -ServicePrincipalId:bigint -Classification:Low -PermissionId:'N,U'
Connect-AzureAD: One or more errors occurred. (Could not load type 'System.Security.Cryptography.SHA256Cng' from assembly 'System.Core, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089'.): Could not load type 'System.Security.Cryptography.SHA256Cng' from assembly 'System.Core, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089'.
Connect-AzureAD: One or more errors occurred. (Could not load type 'System.Security.Cryptography.SHA256Cng' from assembly 'System.Core, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089'.)
Connect-AzureAD: Could not load type 'System.Security.Cryptography.SHA256Cng' from assembly 'System.Core, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089'.
Connect-AzureAD: One or more errors occurred. (Could not load type 'System.Security.Cryptography.SHA256Cng' from assembly 'System.Core, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089'.): Could not load type 'System.Security.Cryptography.SHA256Cng' from assembly 'System.Core, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089'.

cmdlet Add-AzureADMSApplicationOwner at command pipeline position 1
Supply values for the following parameters:
ObjectId: not null
RefObjectId: low
Add-AzureADMSApplicationOwner: You must call the Connect-AzureAD cmdlet before calling any other cmdlets.
Add-AzureADMSServicePrincipalDelegatedPermissionClassification: You must call the Connect-AzureAD cmdlet before calling any other cmdlets.
PS C:\Program Files\Notepad++> Add-AzureADMSApplicationOwner | AzureADPreview\Add-AzureADMSServicePrincipalDelegatedPermissionClassification -PermissionName:.\autoCompletion\ -ServicePrincipalId:bigint -Classification:Low -PermissionId:'N,U'

cmdlet Add-AzureADMSApplicationOwner at command pipeline position 1
Supply values for the following parameters:
ObjectId:
PS C:\Program Files\Notepad++> Add-AzureADMSApplicationOwner -ObjectId:.\SciLexer.dll | AzureADPreview\Add-AzureADMSServicePrincipalDelegatedPermissionClassification -PermissionName:.\autoCompletion\ -ServicePrincipalId:bigint -Classification:Low -PermissionId:'N,U'

cmdlet Add-AzureADMSApplicationOwner at command pipeline position 1
Supply values for the following parameters:
RefObjectId:
PS C:\Program Files\Notepad++> Add-AzureADMSApplicationOwner -ObjectId:SciLexer.dll  -RefObjectId:LICENSE | AzureADPreview\Add-AzureADMSServicePrincipalDelegatedPermissionClassification -PermissionName:.\autoCompletion\ -ServicePrincipalId:bigint -Classification:Low -PermissionId:'N,U'
Add-AzureADMSApplicationOwner: You must call the Connect-AzureAD cmdlet before calling any other cmdlets.
PS C:\Program Files\Notepad++> cd r:\
Set-Location: Cannot find drive. A drive with the name 'r' does not exist.
PS C:\Program Files\Notepad++> ps chrome

 NPM(K)    PM(M)      WS(M)     CPU(s)      Id  SI ProcessName
 ------    -----      -----     ------      --  -- -----------
     17    35.70      25.03       2.30     824   2 chrome
     16    34.30      17.91       1.81    3124   2 chrome
     17    37.17      34.71       2.08    4024   2 chrome
     28   217.74     254.85      26.48    4644   2 chrome
      9     5.99       2.18       0.03    5152   2 chrome
     25   183.77     240.47      44.34    7676   2 chrome
     31    74.71      75.13      10.30    8216   2 chrome
     67   142.85     174.43      59.02    8380   2 chrome
     13    13.57       5.97       1.20    8636   2 chrome
     31   226.81     278.05      53.97    9076   2 chrome
     19    60.10      29.59       1.14    9260   2 chrome
     22   115.39     146.32      14.16   10776   2 chrome
     15    34.42      29.17       2.06   11824   2 chrome
     17    13.36      10.49       1.30   13352   2 chrome
     45   396.31     392.85      54.64   13628   2 chrome
     15    22.90      42.89       1.33   14484   2 chrome
     20    52.74      95.43       6.45   15152   2 chrome
     13    17.31      21.84       0.09   15420   2 chrome
     16    26.46      14.50       0.86   15504   2 chrome
     15    20.23      33.22       0.19   16284   2 chrome

PS C:\Program Files\Notepad++> ps chrome | Format-List **]






















PS C:\Program Files\Notepad++> ps chrome | Format-List **

Name                       : chrome
Id                         : 824
PriorityClass              : Idle
FileVersion                : 90.0.4430.19
HandleCount                : 290
WorkingSet                 : 25399296
PagedMemorySize            : 37433344
PrivateMemorySize          : 37433344
VirtualMemorySize          : 431034368
TotalProcessorTime         : 00:00:02.2968750
SI                         : 2
Handles                    : 290
VM                         : 2311123439616
WS                         : 25399296
PM                         : 37433344
NPM                        : 17600
Path                       : C:\Program Files\Google\Chrome Dev\Application\chrome.exe
CommandLine                : "C:\Program Files\Google\Chrome Dev\Application\chrome.exe" --type=renderer --field-trial-handle=1624,9494390279174207997,2118100447490828961,131072 --disable-databases --lang=en-US
                             --origin-trial-disabled-features=SecurePaymentConfirmation --device-scale-factor=1.15625 --num-raster-threads=4 --enable-main-frame-before-activation --renderer-client-id=35
                             --no-v8-untrusted-code-mitigations --mojo-platform-channel-handle=3136 /prefetch:1
Parent                     : System.Diagnostics.Process (chrome)
Company                    : Google LLC
CPU                        : 2.296875
ProductVersion             : 90.0.4430.19
Description                : Google Chrome
Product                    : Google Chrome
__NounName                 : Process
SafeHandle                 : Microsoft.Win32.SafeHandles.SafeProcessHandle
Handle                     : 3644
BasePriority               : 4
ExitCode                   :
HasExited                  : False
StartTime                  : 3/9/2021 7:56:19 PM
ExitTime                   :
MachineName                : .
MaxWorkingSet              : 1413120
MinWorkingSet              : 204800
Modules                    : {System.Diagnostics.ProcessModule (chrome.exe), System.Diagnostics.ProcessModule (ntdll.dll), System.Diagnostics.ProcessModule (KERNEL32.DLL), System.Diagnostics.ProcessModule (KERNELBASE.dll)…}
NonpagedSystemMemorySize64 : 17600
NonpagedSystemMemorySize   : 17600
PagedMemorySize64          : 37433344
PagedSystemMemorySize64    : 510160
PagedSystemMemorySize      : 510160
PeakPagedMemorySize64      : 49537024
PeakPagedMemorySize        : 49537024
PeakWorkingSet64           : 83886080
PeakWorkingSet             : 83886080
PeakVirtualMemorySize64    : 2315328487424
PeakVirtualMemorySize      : 341114880
PriorityBoostEnabled       : True
PrivateMemorySize64        : 37433344
ProcessName                : chrome
ProcessorAffinity          : 255
SessionId                  : 2
StartInfo                  :
Threads                    : {15096, 7260, 4416, 3284…}
VirtualMemorySize64        : 2311123439616
EnableRaisingEvents        : False
StandardInput              :
StandardOutput             :
StandardError              :
WorkingSet64               : 25399296
SynchronizingObject        :
MainModule                 : System.Diagnostics.ProcessModule (chrome.exe)
PrivilegedProcessorTime    : 00:00:00.3281250
UserProcessorTime          : 00:00:01.9687500
MainWindowHandle           : 0
MainWindowTitle            :
Responding                 : True
Site                       :
Container                  :

Name                       : chrome
Id                         : 3124
PriorityClass              : Idle
FileVersion                : 90.0.4430.19
HandleCount                : 268
WorkingSet                 : 18202624
PagedMemorySize            : 35971072
PrivateMemorySize          : 35971072
VirtualMemorySize          : 441741312
TotalProcessorTime         : 00:00:01.8125000
SI                         : 2
Handles                    : 268
VM                         : 2311134146560
WS                         : 18202624
PM                         : 35971072
NPM                        : 16784
Path                       : C:\Program Files\Google\Chrome Dev\Application\chrome.exe
CommandLine                : "C:\Program Files\Google\Chrome Dev\Application\chrome.exe" --type=renderer --field-trial-handle=1624,9494390279174207997,2118100447490828961,131072 --disable-databases --lang=en-US
                             --origin-trial-disabled-features=SecurePaymentConfirmation --device-scale-factor=1.15625 --num-raster-threads=4 --enable-main-frame-before-activation --renderer-client-id=23
                             --no-v8-untrusted-code-mitigations --mojo-platform-channel-handle=3132 /prefetch:1
Parent                     : System.Diagnostics.Process (chrome)
Company                    : Google LLC
CPU                        : 1.8125
ProductVersion             : 90.0.4430.19
Description                : Google Chrome
Product                    : Google Chrome
__NounName                 : Process
SafeHandle                 : Microsoft.Win32.SafeHandles.SafeProcessHandle
Handle                     : 5912
BasePriority               : 4
ExitCode                   :
HasExited                  : False
StartTime                  : 3/9/2021 7:48:30 PM
ExitTime                   :
MachineName                : .
MaxWorkingSet              : 1413120
MinWorkingSet              : 204800
Modules                    : {System.Diagnostics.ProcessModule (chrome.exe), System.Diagnostics.ProcessModule (ntdll.dll), System.Diagnostics.ProcessModule (KERNEL32.DLL), System.Diagnostics.ProcessModule (KERNELBASE.dll)…}
NonpagedSystemMemorySize64 : 16784
NonpagedSystemMemorySize   : 16784
PagedMemorySize64          : 35971072
PagedSystemMemorySize64    : 501056
PagedSystemMemorySize      : 501056
PeakPagedMemorySize64      : 44814336
PeakPagedMemorySize        : 44814336
PeakWorkingSet64           : 78127104
PeakWorkingSet             : 78127104
PeakVirtualMemorySize64    : 2315345297408
PeakVirtualMemorySize      : 357924864
PriorityBoostEnabled       : True
PrivateMemorySize64        : 35971072
ProcessName                : chrome
ProcessorAffinity          : 255
SessionId                  : 2
StartInfo                  :
Threads                    : {4184, 13508, 7228, 6248…}
VirtualMemorySize64        : 2311134146560
EnableRaisingEvents        : False
StandardInput              :
StandardOutput             :
StandardError              :
WorkingSet64               : 18202624
SynchronizingObject        :
MainModule                 : System.Diagnostics.ProcessModule (chrome.exe)
PrivilegedProcessorTime    : 00:00:00.2343750
UserProcessorTime          : 00:00:01.5781250
MainWindowHandle           : 0
MainWindowTitle            :
Responding                 : True
Site                       :
Container                  :

Name                       : chrome
Id                         : 4024
PriorityClass              : Idle
FileVersion                : 90.0.4430.19
HandleCount                : 289
WorkingSet                 : 35426304
PagedMemorySize            : 38977536
PrivateMemorySize          : 38977536
VirtualMemorySize          : 426143744
TotalProcessorTime         : 00:00:02.0781250
SI                         : 2
Handles                    : 289
VM                         : 2311118548992
WS                         : 35426304
PM                         : 38977536
NPM                        : 17192
Path                       : C:\Program Files\Google\Chrome Dev\Application\chrome.exe
CommandLine                : "C:\Program Files\Google\Chrome Dev\Application\chrome.exe" --type=renderer --field-trial-handle=1624,9494390279174207997,2118100447490828961,131072 --disable-databases --lang=en-US
                             --origin-trial-disabled-features=SecurePaymentConfirmation --start-stack-profiler --device-scale-factor=1.15625 --num-raster-threads=4 --enable-main-frame-before-activation --renderer-client-id=40
                             --no-v8-untrusted-code-mitigations --mojo-platform-channel-handle=6544 /prefetch:1
Parent                     : System.Diagnostics.Process (chrome)
Company                    : Google LLC
CPU                        : 2.078125
ProductVersion             : 90.0.4430.19
Description                : Google Chrome
Product                    : Google Chrome
__NounName                 : Process
SafeHandle                 : Microsoft.Win32.SafeHandles.SafeProcessHandle
Handle                     : 5568
BasePriority               : 4
ExitCode                   :
HasExited                  : False
StartTime                  : 3/9/2021 7:58:04 PM
ExitTime                   :
MachineName                : .
MaxWorkingSet              : 1413120
MinWorkingSet              : 204800
Modules                    : {System.Diagnostics.ProcessModule (chrome.exe), System.Diagnostics.ProcessModule (ntdll.dll), System.Diagnostics.ProcessModule (KERNEL32.DLL), System.Diagnostics.ProcessModule (KERNELBASE.dll)…}
NonpagedSystemMemorySize64 : 17192
NonpagedSystemMemorySize   : 17192
PagedMemorySize64          : 38977536
PagedSystemMemorySize64    : 513408
PagedSystemMemorySize      : 513408
PeakPagedMemorySize64      : 46010368
PeakPagedMemorySize        : 46010368
PeakWorkingSet64           : 77352960
PeakWorkingSet             : 77352960
PeakVirtualMemorySize64    : 2315336876032
PeakVirtualMemorySize      : 349503488
PriorityBoostEnabled       : True
PrivateMemorySize64        : 38977536
ProcessName                : chrome
ProcessorAffinity          : 255
SessionId                  : 2
StartInfo                  :
Threads                    : {12052, 6600, 10640, 15180…}
VirtualMemorySize64        : 2311118548992
EnableRaisingEvents        : False
StandardInput              :
StandardOutput             :
StandardError              :
WorkingSet64               : 35426304
SynchronizingObject        :
MainModule                 : System.Diagnostics.ProcessModule (chrome.exe)
PrivilegedProcessorTime    : 00:00:00.3437500
UserProcessorTime          : 00:00:01.7343750
MainWindowHandle           : 0
MainWindowTitle            :
Responding                 : True
Site                       :
Container                  :

Name                       : chrome
Id                         : 4644
PriorityClass              : Normal
FileVersion                : 90.0.4430.19
HandleCount                : 481
WorkingSet                 : 267345920
PagedMemorySize            : 228274176
PrivateMemorySize          : 228274176
VirtualMemorySize          : 560046080
TotalProcessorTime         : 00:00:26.4843750
SI                         : 2
Handles                    : 481
VM                         : 2319842385920
WS                         : 267345920
PM                         : 228274176
NPM                        : 27936
Path                       : C:\Program Files\Google\Chrome Dev\Application\chrome.exe
CommandLine                : "C:\Program Files\Google\Chrome Dev\Application\chrome.exe" --type=renderer --field-trial-handle=1624,9494390279174207997,2118100447490828961,131072 --disable-databases --lang=en-US
                             --origin-trial-disabled-features=SecurePaymentConfirmation --device-scale-factor=1.15625 --num-raster-threads=4 --enable-main-frame-before-activation --renderer-client-id=56
                             --no-v8-untrusted-code-mitigations --mojo-platform-channel-handle=3820 /prefetch:1
Parent                     : System.Diagnostics.Process (chrome)
Company                    : Google LLC
CPU                        : 26.484375
ProductVersion             : 90.0.4430.19
Description                : Google Chrome
Product                    : Google Chrome
__NounName                 : Process
SafeHandle                 : Microsoft.Win32.SafeHandles.SafeProcessHandle
Handle                     : 5804
BasePriority               : 8
ExitCode                   :
HasExited                  : False
StartTime                  : 3/9/2021 8:10:13 PM
ExitTime                   :
MachineName                : .
MaxWorkingSet              : 1413120
MinWorkingSet              : 204800
Modules                    : {System.Diagnostics.ProcessModule (chrome.exe), System.Diagnostics.ProcessModule (ntdll.dll), System.Diagnostics.ProcessModule (KERNEL32.DLL), System.Diagnostics.ProcessModule (KERNELBASE.dll)…}
NonpagedSystemMemorySize64 : 27936
NonpagedSystemMemorySize   : 27936
PagedMemorySize64          : 228274176
PagedSystemMemorySize64    : 555384
PagedSystemMemorySize      : 555384
PeakPagedMemorySize64      : 392019968
PeakPagedMemorySize        : 392019968
PeakWorkingSet64           : 425492480
PeakWorkingSet             : 425492480
PeakVirtualMemorySize64    : 2324109434880
PeakVirtualMemorySize      : 532127744
PriorityBoostEnabled       : True
PrivateMemorySize64        : 228274176
ProcessName                : chrome
ProcessorAffinity          : 255
SessionId                  : 2
StartInfo                  :
Threads                    : {13636, 15832, 14028, 5904…}
VirtualMemorySize64        : 2319842385920
EnableRaisingEvents        : False
StandardInput              :
StandardOutput             :
StandardError              :
WorkingSet64               : 267345920
SynchronizingObject        :
MainModule                 : System.Diagnostics.ProcessModule (chrome.exe)
PrivilegedProcessorTime    : 00:00:02.9531250
UserProcessorTime          : 00:00:23.5312500
MainWindowHandle           : 0
MainWindowTitle            :
Responding                 : True
Site                       :
Container                  :

Name                       : chrome
Id                         : 5152
PriorityClass              : Normal
FileVersion                : 90.0.4430.19
HandleCount                : 242
WorkingSet                 : 2265088
PagedMemorySize            : 6279168
PrivateMemorySize          : 6279168
VirtualMemorySize          : 160329728
TotalProcessorTime         : 00:00:00.0312500
SI                         : 2
Handles                    : 242
VM                         : 2272198029312
WS                         : 2265088
PM                         : 6279168
NPM                        : 9240
Path                       : C:\Program Files\Google\Chrome Dev\Application\chrome.exe
CommandLine                : "C:\Program Files\Google\Chrome Dev\Application\chrome.exe" --type=crashpad-handler "--user-data-dir=C:\Users\UTLUSR\AppData\Local\Google\Chrome Dev\User Data" /prefetch:7
                             --monitor-self-annotation=ptype=crashpad-handler "--database=C:\Users\UTLUSR\AppData\Local\Google\Chrome Dev\User Data\Crashpad" "--metrics-dir=C:\Users\UTLUSR\AppData\Local\Google\Chrome Dev\User Data"
                             --url=https://clients2.google.com/cr/report --annotation=channel=dev --annotation=plat=Win64 --annotation=prod=Chrome --annotation=ver=90.0.4430.19
                             --initial-client-data=0xf8,0xfc,0x100,0xd4,0x104,0x7ffc99612920,0x7ffc99612930,0x7ffc99612940
Parent                     : System.Diagnostics.Process (chrome)
Company                    : Google LLC
CPU                        : 0.03125
ProductVersion             : 90.0.4430.19
Description                : Google Chrome
Product                    : Google Chrome
__NounName                 : Process
SafeHandle                 : Microsoft.Win32.SafeHandles.SafeProcessHandle
Handle                     : 5216
BasePriority               : 8
ExitCode                   :
HasExited                  : False
StartTime                  : 3/9/2021 7:47:30 PM
ExitTime                   :
MachineName                : .
MaxWorkingSet              : 1413120
MinWorkingSet              : 204800
Modules                    : {System.Diagnostics.ProcessModule (chrome.exe), System.Diagnostics.ProcessModule (ntdll.dll), System.Diagnostics.ProcessModule (KERNEL32.DLL), System.Diagnostics.ProcessModule (KERNELBASE.dll)…}
NonpagedSystemMemorySize64 : 9240
NonpagedSystemMemorySize   : 9240
PagedMemorySize64          : 6279168
PagedSystemMemorySize64    : 133224
PagedSystemMemorySize      : 133224
PeakPagedMemorySize64      : 6361088
PeakPagedMemorySize        : 6361088
PeakWorkingSet64           : 7675904
PeakWorkingSet             : 7675904
PeakVirtualMemorySize64    : 2272230277120
PeakVirtualMemorySize      : 192577536
PriorityBoostEnabled       : True
PrivateMemorySize64        : 6279168
ProcessName                : chrome
ProcessorAffinity          : 255
SessionId                  : 2
StartInfo                  :
Threads                    : {6552, 10180, 14272, 9736…}
VirtualMemorySize64        : 2272198029312
EnableRaisingEvents        : False
StandardInput              :
StandardOutput             :
StandardError              :
WorkingSet64               : 2265088
SynchronizingObject        :
MainModule                 : System.Diagnostics.ProcessModule (chrome.exe)
PrivilegedProcessorTime    : 00:00:00.0156250
UserProcessorTime          : 00:00:00.0156250
MainWindowHandle           : 0
MainWindowTitle            :
Responding                 : True
Site                       :
Container                  :

Name                       : chrome
Id                         : 7676
PriorityClass              : Normal
FileVersion                : 90.0.4430.19
HandleCount                : 375
WorkingSet                 : 250093568
PagedMemorySize            : 191324160
PrivateMemorySize          : 191324160
VirtualMemorySize          : 557608960
TotalProcessorTime         : 00:00:44.8281250
SI                         : 2
Handles                    : 375
VM                         : 2311250014208
WS                         : 250093568
PM                         : 191324160
NPM                        : 25840
Path                       : C:\Program Files\Google\Chrome Dev\Application\chrome.exe
CommandLine                : "C:\Program Files\Google\Chrome Dev\Application\chrome.exe" --type=renderer --field-trial-handle=1624,9494390279174207997,2118100447490828961,131072 --disable-databases --lang=en-US
                             --origin-trial-disabled-features=SecurePaymentConfirmation --device-scale-factor=1.15625 --num-raster-threads=4 --enable-main-frame-before-activation --renderer-client-id=58
                             --no-v8-untrusted-code-mitigations --mojo-platform-channel-handle=5664 /prefetch:1
Parent                     : System.Diagnostics.Process (chrome)
Company                    : Google LLC
CPU                        : 44.828125
ProductVersion             : 90.0.4430.19
Description                : Google Chrome
Product                    : Google Chrome
__NounName                 : Process
SafeHandle                 : Microsoft.Win32.SafeHandles.SafeProcessHandle
Handle                     : 5908
BasePriority               : 8
ExitCode                   :
HasExited                  : False
StartTime                  : 3/9/2021 8:11:45 PM
ExitTime                   :
MachineName                : .
MaxWorkingSet              : 1413120
MinWorkingSet              : 204800
Modules                    : {System.Diagnostics.ProcessModule (chrome.exe), System.Diagnostics.ProcessModule (ntdll.dll), System.Diagnostics.ProcessModule (KERNEL32.DLL), System.Diagnostics.ProcessModule (KERNELBASE.dll)…}
NonpagedSystemMemorySize64 : 25840
NonpagedSystemMemorySize   : 25840
PagedMemorySize64          : 191324160
PagedSystemMemorySize64    : 570464
PagedSystemMemorySize      : 570464
PeakPagedMemorySize64      : 224198656
PeakPagedMemorySize        : 224198656
PeakWorkingSet64           : 283181056
PeakWorkingSet             : 283181056
PeakVirtualMemorySize64    : 2315328487424
PeakVirtualMemorySize      : 341114880
PriorityBoostEnabled       : True
PrivateMemorySize64        : 191324160
ProcessName                : chrome
ProcessorAffinity          : 255
SessionId                  : 2
StartInfo                  :
Threads                    : {13740, 7704, 12080, 1372…}
VirtualMemorySize64        : 2311250014208
EnableRaisingEvents        : False
StandardInput              :
StandardOutput             :
StandardError              :
WorkingSet64               : 250093568
SynchronizingObject        :
MainModule                 : System.Diagnostics.ProcessModule (chrome.exe)
PrivilegedProcessorTime    : 00:00:03.3906250
UserProcessorTime          : 00:00:41.4375000
MainWindowHandle           : 0
MainWindowTitle            :
Responding                 : True
Site                       :
Container                  :

Name                       : chrome
Id                         : 8216
PriorityClass              : Normal
FileVersion                : 90.0.4430.19
HandleCount                : 368
WorkingSet                 : 79138816
PagedMemorySize            : 78807040
PrivateMemorySize          : 78807040
VirtualMemorySize          : 412590080
TotalProcessorTime         : 00:00:10.4218750
SI                         : 2
Handles                    : 368
VM                         : 2306810028032
WS                         : 79138816
PM                         : 78807040
NPM                        : 30152
Path                       : C:\Program Files\Google\Chrome Dev\Application\chrome.exe
CommandLine                : "C:\Program Files\Google\Chrome Dev\Application\chrome.exe" --type=utility --utility-sub-type=network.mojom.NetworkService --field-trial-handle=1624,9494390279174207997,2118100447490828961,131072
                             --lang=en-US --service-sandbox-type=none --start-stack-profiler --mojo-platform-channel-handle=2092 /prefetch:8
Parent                     : System.Diagnostics.Process (chrome)
Company                    : Google LLC
CPU                        : 10.421875
ProductVersion             : 90.0.4430.19
Description                : Google Chrome
Product                    : Google Chrome
__NounName                 : Process
SafeHandle                 : Microsoft.Win32.SafeHandles.SafeProcessHandle
Handle                     : 4936
BasePriority               : 8
ExitCode                   :
HasExited                  : False
StartTime                  : 3/9/2021 7:47:30 PM
ExitTime                   :
MachineName                : .
MaxWorkingSet              : 1413120
MinWorkingSet              : 204800
Modules                    : {System.Diagnostics.ProcessModule (chrome.exe), System.Diagnostics.ProcessModule (ntdll.dll), System.Diagnostics.ProcessModule (KERNEL32.DLL), System.Diagnostics.ProcessModule (KERNELBASE.dll)…}
NonpagedSystemMemorySize64 : 30152
NonpagedSystemMemorySize   : 30152
PagedMemorySize64          : 78807040
PagedSystemMemorySize64    : 563840
PagedSystemMemorySize      : 563840
PeakPagedMemorySize64      : 81543168
PeakPagedMemorySize        : 81543168
PeakWorkingSet64           : 81072128
PeakWorkingSet             : 81072128
PeakVirtualMemorySize64    : 2306869796864
PeakVirtualMemorySize      : 472358912
PriorityBoostEnabled       : True
PrivateMemorySize64        : 78807040
ProcessName                : chrome
ProcessorAffinity          : 255
SessionId                  : 2
StartInfo                  :
Threads                    : {12424, 5732, 10252, 14096…}
VirtualMemorySize64        : 2306810028032
EnableRaisingEvents        : False
StandardInput              :
StandardOutput             :
StandardError              :
WorkingSet64               : 79138816
SynchronizingObject        :
MainModule                 : System.Diagnostics.ProcessModule (chrome.exe)
PrivilegedProcessorTime    : 00:00:03.5312500
UserProcessorTime          : 00:00:06.8906250
MainWindowHandle           : 0
MainWindowTitle            :
Responding                 : True
Site                       :
Container                  :

Name                       : chrome
Id                         : 8380
PriorityClass              : Normal
FileVersion                : 90.0.4430.19
HandleCount                : 1846
WorkingSet                 : 178987008
PagedMemorySize            : 149778432
PrivateMemorySize          : 149778432
VirtualMemorySize          : 831762432
TotalProcessorTime         : 00:00:59.1250000
SI                         : 2
Handles                    : 1846
VM                         : 2307229200384
WS                         : 178987008
PM                         : 149778432
NPM                        : 67440
Path                       : C:\Program Files\Google\Chrome Dev\Application\chrome.exe
CommandLine                : "C:\Program Files\Google\Chrome Dev\Application\chrome.exe" -incognito --disable-cookies
Parent                     : System.Diagnostics.Process (explorer)
Company                    : Google LLC
CPU                        : 59.125
ProductVersion             : 90.0.4430.19
Description                : Google Chrome
Product                    : Google Chrome
__NounName                 : Process
SafeHandle                 : Microsoft.Win32.SafeHandles.SafeProcessHandle
Handle                     : 2752
BasePriority               : 8
ExitCode                   :
HasExited                  : False
StartTime                  : 3/9/2021 7:47:30 PM
ExitTime                   :
MachineName                : .
MaxWorkingSet              : 1413120
MinWorkingSet              : 204800
Modules                    : {System.Diagnostics.ProcessModule (chrome.exe), System.Diagnostics.ProcessModule (ntdll.dll), System.Diagnostics.ProcessModule (KERNEL32.DLL), System.Diagnostics.ProcessModule (KERNELBASE.dll)…}
NonpagedSystemMemorySize64 : 67440
NonpagedSystemMemorySize   : 67440
PagedMemorySize64          : 149778432
PagedSystemMemorySize64    : 1105056
PagedSystemMemorySize      : 1105056
PeakPagedMemorySize64      : 181358592
PeakPagedMemorySize        : 181358592
PeakWorkingSet64           : 218583040
PeakWorkingSet             : 218583040
PeakVirtualMemorySize64    : 2307306975232
PeakVirtualMemorySize      : 909537280
PriorityBoostEnabled       : True
PrivateMemorySize64        : 149778432
ProcessName                : chrome
ProcessorAffinity          : 255
SessionId                  : 2
StartInfo                  :
Threads                    : {8088, 5528, 7300, 8516…}
VirtualMemorySize64        : 2307229200384
EnableRaisingEvents        : False
StandardInput              :
StandardOutput             :
StandardError              :
WorkingSet64               : 178987008
SynchronizingObject        :
MainModule                 : System.Diagnostics.ProcessModule (chrome.exe)
PrivilegedProcessorTime    : 00:00:25.9687500
UserProcessorTime          : 00:00:33.1562500
MainWindowHandle           : 1707366
MainWindowTitle            : Administrivia - YouTube - Google Chrome
Responding                 : True
Site                       :
Container                  :

Name                       : chrome
Id                         : 8636
PriorityClass              : Normal
FileVersion                : 90.0.4430.19
HandleCount                : 213
WorkingSet                 : 6254592
PagedMemorySize            : 14229504
PrivateMemorySize          : 14229504
VirtualMemorySize          : 362663936
TotalProcessorTime         : 00:00:01.2031250
SI                         : 2
Handles                    : 213
VM                         : 2306760101888
WS                         : 6254592
PM                         : 14229504
NPM                        : 13112
Path                       : C:\Program Files\Google\Chrome Dev\Application\chrome.exe
CommandLine                : "C:\Program Files\Google\Chrome Dev\Application\chrome.exe" --type=utility --utility-sub-type=storage.mojom.StorageService --field-trial-handle=1624,9494390279174207997,2118100447490828961,131072
                             --lang=en-US --service-sandbox-type=utility --mojo-platform-channel-handle=2576 /prefetch:8
Parent                     : System.Diagnostics.Process (chrome)
Company                    : Google LLC
CPU                        : 1.203125
ProductVersion             : 90.0.4430.19
Description                : Google Chrome
Product                    : Google Chrome
__NounName                 : Process
SafeHandle                 : Microsoft.Win32.SafeHandles.SafeProcessHandle
Handle                     : 5272
BasePriority               : 8
ExitCode                   :
HasExited                  : False
StartTime                  : 3/9/2021 7:47:30 PM
ExitTime                   :
MachineName                : .
MaxWorkingSet              : 1413120
MinWorkingSet              : 204800
Modules                    : {System.Diagnostics.ProcessModule (chrome.exe), System.Diagnostics.ProcessModule (ntdll.dll), System.Diagnostics.ProcessModule (KERNEL32.DLL), System.Diagnostics.ProcessModule (KERNELBASE.dll)…}
NonpagedSystemMemorySize64 : 13112
NonpagedSystemMemorySize   : 13112
PagedMemorySize64          : 14229504
PagedSystemMemorySize64    : 506920
PagedSystemMemorySize      : 506920
PeakPagedMemorySize64      : 14299136
PeakPagedMemorySize        : 14299136
PeakWorkingSet64           : 17297408
PeakWorkingSet             : 17297408
PeakVirtualMemorySize64    : 2306776879104
PeakVirtualMemorySize      : 379441152
PriorityBoostEnabled       : True
PrivateMemorySize64        : 14229504
ProcessName                : chrome
ProcessorAffinity          : 255
SessionId                  : 2
StartInfo                  :
Threads                    : {7240, 12456, 2684, 14988…}
VirtualMemorySize64        : 2306760101888
EnableRaisingEvents        : False
StandardInput              :
StandardOutput             :
StandardError              :
WorkingSet64               : 6254592
SynchronizingObject        :
MainModule                 : System.Diagnostics.ProcessModule (chrome.exe)
PrivilegedProcessorTime    : 00:00:00.5312500
UserProcessorTime          : 00:00:00.6718750
MainWindowHandle           : 0
MainWindowTitle            :
Responding                 : True
Site                       :
Container                  :

Name                       : chrome
Id                         : 9076
PriorityClass              : Normal
FileVersion                : 90.0.4430.19
HandleCount                : 353
WorkingSet                 : 288559104
PagedMemorySize            : 235995136
PrivateMemorySize          : 235995136
VirtualMemorySize          : 619520000
TotalProcessorTime         : 00:00:57.7500000
SI                         : 2
Handles                    : 353
VM                         : 2311311925248
WS                         : 288559104
PM                         : 235995136
NPM                        : 31336
Path                       : C:\Program Files\Google\Chrome Dev\Application\chrome.exe
CommandLine                : "C:\Program Files\Google\Chrome Dev\Application\chrome.exe" --type=renderer --field-trial-handle=1624,9494390279174207997,2118100447490828961,131072 --disable-databases --lang=en-US
                             --origin-trial-disabled-features=SecurePaymentConfirmation --device-scale-factor=1.15625 --num-raster-threads=4 --enable-main-frame-before-activation --renderer-client-id=42
                             --no-v8-untrusted-code-mitigations --mojo-platform-channel-handle=7052 /prefetch:1
Parent                     : System.Diagnostics.Process (chrome)
Company                    : Google LLC
CPU                        : 57.75
ProductVersion             : 90.0.4430.19
Description                : Google Chrome
Product                    : Google Chrome
__NounName                 : Process
SafeHandle                 : Microsoft.Win32.SafeHandles.SafeProcessHandle
Handle                     : 6140
BasePriority               : 8
ExitCode                   :
HasExited                  : False
StartTime                  : 3/9/2021 8:06:30 PM
ExitTime                   :
MachineName                : .
MaxWorkingSet              : 1413120
MinWorkingSet              : 204800
Modules                    : {System.Diagnostics.ProcessModule (chrome.exe), System.Diagnostics.ProcessModule (ntdll.dll), System.Diagnostics.ProcessModule (KERNEL32.DLL), System.Diagnostics.ProcessModule (KERNELBASE.dll)…}
NonpagedSystemMemorySize64 : 31336
NonpagedSystemMemorySize   : 31336
PagedMemorySize64          : 235995136
PagedSystemMemorySize64    : 539440
PagedSystemMemorySize      : 539440
PeakPagedMemorySize64      : 280043520
PeakPagedMemorySize        : 280043520
PeakWorkingSet64           : 345870336
PeakWorkingSet             : 345870336
PeakVirtualMemorySize64    : 2324178251776
PeakVirtualMemorySize      : 600944640
PriorityBoostEnabled       : True
PrivateMemorySize64        : 235995136
ProcessName                : chrome
ProcessorAffinity          : 255
SessionId                  : 2
StartInfo                  :
Threads                    : {6460, 472, 7916, 1692…}
VirtualMemorySize64        : 2311311925248
EnableRaisingEvents        : False
StandardInput              :
StandardOutput             :
StandardError              :
WorkingSet64               : 288559104
SynchronizingObject        :
MainModule                 : System.Diagnostics.ProcessModule (chrome.exe)
PrivilegedProcessorTime    : 00:00:05.1562500
UserProcessorTime          : 00:00:52.5937500
MainWindowHandle           : 0
MainWindowTitle            :
Responding                 : True
Site                       :
Container                  :

Name                       : chrome
Id                         : 9260
PriorityClass              : Idle
FileVersion                : 90.0.4430.19
HandleCount                : 273
WorkingSet                 : 30105600
PagedMemorySize            : 63029248
PrivateMemorySize          : 63029248
VirtualMemorySize          : 446767104
TotalProcessorTime         : 00:00:01.1406250
SI                         : 2
Handles                    : 273
VM                         : 2311139172352
WS                         : 30105600
PM                         : 63029248
NPM                        : 19640
Path                       : C:\Program Files\Google\Chrome Dev\Application\chrome.exe
CommandLine                : "C:\Program Files\Google\Chrome Dev\Application\chrome.exe" --type=renderer --field-trial-handle=1624,9494390279174207997,2118100447490828961,131072 --disable-databases --lang=en-US
                             --origin-trial-disabled-features=SecurePaymentConfirmation --device-scale-factor=1.15625 --num-raster-threads=4 --enable-main-frame-before-activation --renderer-client-id=27
                             --no-v8-untrusted-code-mitigations --mojo-platform-channel-handle=6008 /prefetch:1
Parent                     : System.Diagnostics.Process (chrome)
Company                    : Google LLC
CPU                        : 1.140625
ProductVersion             : 90.0.4430.19
Description                : Google Chrome
Product                    : Google Chrome
__NounName                 : Process
SafeHandle                 : Microsoft.Win32.SafeHandles.SafeProcessHandle
Handle                     : 3548
BasePriority               : 4
ExitCode                   :
HasExited                  : False
StartTime                  : 3/9/2021 7:48:49 PM
ExitTime                   :
MachineName                : .
MaxWorkingSet              : 1413120
MinWorkingSet              : 204800
Modules                    : {System.Diagnostics.ProcessModule (chrome.exe), System.Diagnostics.ProcessModule (ntdll.dll), System.Diagnostics.ProcessModule (KERNEL32.DLL), System.Diagnostics.ProcessModule (KERNELBASE.dll)…}
NonpagedSystemMemorySize64 : 19640
NonpagedSystemMemorySize   : 19640
PagedMemorySize64          : 63029248
PagedSystemMemorySize64    : 509016
PagedSystemMemorySize      : 509016
PeakPagedMemorySize64      : 76734464
PeakPagedMemorySize        : 76734464
PeakWorkingSet64           : 103862272
PeakWorkingSet             : 103862272
PeakVirtualMemorySize64    : 2315328487424
PeakVirtualMemorySize      : 341114880
PriorityBoostEnabled       : True
PrivateMemorySize64        : 63029248
ProcessName                : chrome
ProcessorAffinity          : 255
SessionId                  : 2
StartInfo                  :
Threads                    : {16092, 3036, 2228, 6024…}
VirtualMemorySize64        : 2311139172352
EnableRaisingEvents        : False
StandardInput              :
StandardOutput             :
StandardError              :
WorkingSet64               : 30105600
SynchronizingObject        :
MainModule                 : System.Diagnostics.ProcessModule (chrome.exe)
PrivilegedProcessorTime    : 00:00:00.1406250
UserProcessorTime          : 00:00:01
MainWindowHandle           : 0
MainWindowTitle            :
Responding                 : True
Site                       :
Container                  :

Name                       : chrome
Id                         : 10776
PriorityClass              : Idle
FileVersion                : 90.0.4430.19
HandleCount                : 449
WorkingSet                 : 151764992
PagedMemorySize            : 120287232
PrivateMemorySize          : 120287232
VirtualMemorySize          : 544436224
TotalProcessorTime         : 00:00:14.2656250
SI                         : 2
Handles                    : 449
VM                         : 2311236841472
WS                         : 151764992
PM                         : 120287232
NPM                        : 22904
Path                       : C:\Program Files\Google\Chrome Dev\Application\chrome.exe
CommandLine                : "C:\Program Files\Google\Chrome Dev\Application\chrome.exe" --type=renderer --field-trial-handle=1624,9494390279174207997,2118100447490828961,131072 --disable-databases --lang=en-US --extension-process
                             --origin-trial-disabled-features=SecurePaymentConfirmation --device-scale-factor=1.15625 --num-raster-threads=4 --enable-main-frame-before-activation --renderer-client-id=49
                             --no-v8-untrusted-code-mitigations --mojo-platform-channel-handle=1676 /prefetch:1
Parent                     : System.Diagnostics.Process (chrome)
Company                    : Google LLC
CPU                        : 14.265625
ProductVersion             : 90.0.4430.19
Description                : Google Chrome
Product                    : Google Chrome
__NounName                 : Process
SafeHandle                 : Microsoft.Win32.SafeHandles.SafeProcessHandle
Handle                     : 5996
BasePriority               : 4
ExitCode                   :
HasExited                  : False
StartTime                  : 3/9/2021 8:07:42 PM
ExitTime                   :
MachineName                : .
MaxWorkingSet              : 1413120
MinWorkingSet              : 204800
Modules                    : {System.Diagnostics.ProcessModule (chrome.exe), System.Diagnostics.ProcessModule (ntdll.dll), System.Diagnostics.ProcessModule (KERNEL32.DLL), System.Diagnostics.ProcessModule (KERNELBASE.dll)…}
NonpagedSystemMemorySize64 : 22904
NonpagedSystemMemorySize   : 22904
PagedMemorySize64          : 120287232
PagedSystemMemorySize64    : 618192
PagedSystemMemorySize      : 618192
PeakPagedMemorySize64      : 138579968
PeakPagedMemorySize        : 138579968
PeakWorkingSet64           : 174206976
PeakWorkingSet             : 174206976
PeakVirtualMemorySize64    : 2319857709056
PeakVirtualMemorySize      : 575369216
PriorityBoostEnabled       : True
PrivateMemorySize64        : 120287232
ProcessName                : chrome
ProcessorAffinity          : 255
SessionId                  : 2
StartInfo                  :
Threads                    : {7948, 14740, 10044, 14488…}
VirtualMemorySize64        : 2311236841472
EnableRaisingEvents        : False
StandardInput              :
StandardOutput             :
StandardError              :
WorkingSet64               : 151764992
SynchronizingObject        :
MainModule                 : System.Diagnostics.ProcessModule (chrome.exe)
PrivilegedProcessorTime    : 00:00:00.9218750
UserProcessorTime          : 00:00:13.3437500
MainWindowHandle           : 0
MainWindowTitle            :
Responding                 : True
Site                       :
Container                  :

Name                       : chrome
Id                         : 11824
PriorityClass              : Idle
FileVersion                : 90.0.4430.19
HandleCount                : 249
WorkingSet                 : 30060544
PagedMemorySize            : 36225024
PrivateMemorySize          : 36225024
VirtualMemorySize          : 428511232
TotalProcessorTime         : 00:00:02.0781250
SI                         : 2
Handles                    : 249
VM                         : 2311120916480
WS                         : 30060544
PM                         : 36225024
NPM                        : 15832
Path                       : C:\Program Files\Google\Chrome Dev\Application\chrome.exe
CommandLine                : "C:\Program Files\Google\Chrome Dev\Application\chrome.exe" --type=renderer --field-trial-handle=1624,9494390279174207997,2118100447490828961,131072 --disable-databases --lang=en-US
                             --origin-trial-disabled-features=SecurePaymentConfirmation --device-scale-factor=1.15625 --num-raster-threads=4 --enable-main-frame-before-activation --renderer-client-id=28
                             --no-v8-untrusted-code-mitigations --mojo-platform-channel-handle=5336 /prefetch:1
Parent                     : System.Diagnostics.Process (chrome)
Company                    : Google LLC
CPU                        : 2.078125
ProductVersion             : 90.0.4430.19
Description                : Google Chrome
Product                    : Google Chrome
__NounName                 : Process
SafeHandle                 : Microsoft.Win32.SafeHandles.SafeProcessHandle
Handle                     : 3608
BasePriority               : 4
ExitCode                   :
HasExited                  : False
StartTime                  : 3/9/2021 7:49:00 PM
ExitTime                   :
MachineName                : .
MaxWorkingSet              : 1413120
MinWorkingSet              : 204800
Modules                    : {System.Diagnostics.ProcessModule (chrome.exe), System.Diagnostics.ProcessModule (ntdll.dll), System.Diagnostics.ProcessModule (KERNEL32.DLL), System.Diagnostics.ProcessModule (KERNELBASE.dll)…}
NonpagedSystemMemorySize64 : 15832
NonpagedSystemMemorySize   : 15832
PagedMemorySize64          : 36225024
PagedSystemMemorySize64    : 497536
PagedSystemMemorySize      : 497536
PeakPagedMemorySize64      : 40591360
PeakPagedMemorySize        : 40591360
PeakWorkingSet64           : 72880128
PeakWorkingSet             : 72880128
PeakVirtualMemorySize64    : 2315345272832
PeakVirtualMemorySize      : 357900288
PriorityBoostEnabled       : True
PrivateMemorySize64        : 36225024
ProcessName                : chrome
ProcessorAffinity          : 255
SessionId                  : 2
StartInfo                  :
Threads                    : {8036, 14196, 4864, 16108…}
VirtualMemorySize64        : 2311120916480
EnableRaisingEvents        : False
StandardInput              :
StandardOutput             :
StandardError              :
WorkingSet64               : 30060544
SynchronizingObject        :
MainModule                 : System.Diagnostics.ProcessModule (chrome.exe)
PrivilegedProcessorTime    : 00:00:00.5000000
UserProcessorTime          : 00:00:01.5781250
MainWindowHandle           : 0
MainWindowTitle            :
Responding                 : True
Site                       :
Container                  :

Name                       : chrome
Id                         : 13352
PriorityClass              : Normal
FileVersion                : 90.0.4430.19
HandleCount                : 299
WorkingSet                 : 10952704
PagedMemorySize            : 14012416
PrivateMemorySize          : 14012416
VirtualMemorySize          : 372817920
TotalProcessorTime         : 00:00:01.3750000
SI                         : 2
Handles                    : 299
VM                         : 2306770255872
WS                         : 10952704
PM                         : 14012416
NPM                        : 17856
Path                       : C:\Program Files\Google\Chrome Dev\Application\chrome.exe
CommandLine                : "C:\Program Files\Google\Chrome Dev\Application\chrome.exe" --type=utility --utility-sub-type=audio.mojom.AudioService --field-trial-handle=1624,9494390279174207997,2118100447490828961,131072 --lang=en-US
                             --service-sandbox-type=audio --mojo-platform-channel-handle=1564 /prefetch:8
Parent                     : System.Diagnostics.Process (chrome)
Company                    : Google LLC
CPU                        : 1.375
ProductVersion             : 90.0.4430.19
Description                : Google Chrome
Product                    : Google Chrome
__NounName                 : Process
SafeHandle                 : Microsoft.Win32.SafeHandles.SafeProcessHandle
Handle                     : 4304
BasePriority               : 8
ExitCode                   :
HasExited                  : False
StartTime                  : 3/9/2021 7:49:03 PM
ExitTime                   :
MachineName                : .
MaxWorkingSet              : 1413120
MinWorkingSet              : 204800
Modules                    : {System.Diagnostics.ProcessModule (chrome.exe), System.Diagnostics.ProcessModule (ntdll.dll), System.Diagnostics.ProcessModule (KERNEL32.DLL), System.Diagnostics.ProcessModule (KERNELBASE.dll)…}
NonpagedSystemMemorySize64 : 17856
NonpagedSystemMemorySize   : 17856
PagedMemorySize64          : 14012416
PagedSystemMemorySize64    : 540896
PagedSystemMemorySize      : 540896
PeakPagedMemorySize64      : 14094336
PeakPagedMemorySize        : 14094336
PeakWorkingSet64           : 17375232
PeakWorkingSet             : 17375232
PeakVirtualMemorySize64    : 2306787033088
PeakVirtualMemorySize      : 389595136
PriorityBoostEnabled       : True
PrivateMemorySize64        : 14012416
ProcessName                : chrome
ProcessorAffinity          : 255
SessionId                  : 2
StartInfo                  :
Threads                    : {7048, 16132, 12068, 10464…}
VirtualMemorySize64        : 2306770255872
EnableRaisingEvents        : False
StandardInput              :
StandardOutput             :
StandardError              :
WorkingSet64               : 10952704
SynchronizingObject        :
MainModule                 : System.Diagnostics.ProcessModule (chrome.exe)
PrivilegedProcessorTime    : 00:00:00.4843750
UserProcessorTime          : 00:00:00.8906250
MainWindowHandle           : 0
MainWindowTitle            :
Responding                 : True
Site                       :
Container                  :

Name                       : chrome
Id                         : 13628
PriorityClass              : AboveNormal
FileVersion                : 90.0.4430.19
HandleCount                : 1464
WorkingSet                 : 362639360
PagedMemorySize            : 366133248
PrivateMemorySize          : 366133248
VirtualMemorySize          : 1363939328
TotalProcessorTime         : 00:00:57.4218750
SI                         : 2
Handles                    : 1464
VM                         : 2307761377280
WS                         : 362639360
PM                         : 366133248
NPM                        : 45936
Path                       : C:\Program Files\Google\Chrome Dev\Application\chrome.exe
CommandLine                : "C:\Program Files\Google\Chrome Dev\Application\chrome.exe" --type=gpu-process --field-trial-handle=1624,9494390279174207997,2118100447490828961,131072 --start-stack-profiler --gpu-preferences=SAAAAAAAAADgAA
                             AwAAAAAAAAAAAAAAAAAABgAAAAAAAoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB4AAAAAAAAAHgAAAAAAAAAKAAAAAQAAAAgAAAAAAAAACgAAAAAAAAAMAAAAAAAAAA4AAAAAAAAABAAAAAAAAAAAAAAAAUAAAAQAAAAAAAAAAAAAAAGAAAAEAAAAAAAAAABAAAABQAAABAAAAAAA
                             AAAAQAAAAYAAAAIAAAAAAAAAAgAAAAAAAAA --mojo-platform-channel-handle=1744 /prefetch:2
Parent                     : System.Diagnostics.Process (chrome)
Company                    : Google LLC
CPU                        : 57.46875
ProductVersion             : 90.0.4430.19
Description                : Google Chrome
Product                    : Google Chrome
__NounName                 : Process
SafeHandle                 : Microsoft.Win32.SafeHandles.SafeProcessHandle
Handle                     : 2284
BasePriority               : 10
ExitCode                   :
HasExited                  : False
StartTime                  : 3/9/2021 7:47:30 PM
ExitTime                   :
MachineName                : .
MaxWorkingSet              : 1413120
MinWorkingSet              : 204800
Modules                    : {System.Diagnostics.ProcessModule (chrome.exe), System.Diagnostics.ProcessModule (ntdll.dll), System.Diagnostics.ProcessModule (KERNEL32.DLL), System.Diagnostics.ProcessModule (KERNELBASE.dll)…}
NonpagedSystemMemorySize64 : 45936
NonpagedSystemMemorySize   : 45936
PagedMemorySize64          : 366133248
PagedSystemMemorySize64    : 1164200
PagedSystemMemorySize      : 1164200
PeakPagedMemorySize64      : 579862528
PeakPagedMemorySize        : 579862528
PeakWorkingSet64           : 590487552
PeakWorkingSet             : 590487552
PeakVirtualMemorySize64    : 2307864739840
PeakVirtualMemorySize      : 1467301888
PriorityBoostEnabled       : True
PrivateMemorySize64        : 366133248
ProcessName                : chrome
ProcessorAffinity          : 255
SessionId                  : 2
StartInfo                  :
Threads                    : {8304, 14932, 15260, 1988…}
VirtualMemorySize64        : 2307761377280
EnableRaisingEvents        : False
StandardInput              :
StandardOutput             :
StandardError              :
WorkingSet64               : 362639360
SynchronizingObject        :
MainModule                 : System.Diagnostics.ProcessModule (chrome.exe)
PrivilegedProcessorTime    : 00:00:14.3906250
UserProcessorTime          : 00:00:43.0781250
MainWindowHandle           : 0
MainWindowTitle            :
Responding                 : True
Site                       :
Container                  :

Name                       : chrome
Id                         : 14484
PriorityClass              : Idle
FileVersion                : 90.0.4430.19
HandleCount                : 248
WorkingSet                 : 44044288
PagedMemorySize            : 24014848
PrivateMemorySize          : 24014848
VirtualMemorySize          : 404135936
TotalProcessorTime         : 00:00:01.3281250
SI                         : 2
Handles                    : 248
VM                         : 2311096541184
WS                         : 44044288
PM                         : 24014848
NPM                        : 15152
Path                       : C:\Program Files\Google\Chrome Dev\Application\chrome.exe
CommandLine                : "C:\Program Files\Google\Chrome Dev\Application\chrome.exe" --type=renderer --field-trial-handle=1624,9494390279174207997,2118100447490828961,131072 --disable-databases --lang=en-US
                             --origin-trial-disabled-features=SecurePaymentConfirmation --device-scale-factor=1.15625 --num-raster-threads=4 --enable-main-frame-before-activation --renderer-client-id=54
                             --no-v8-untrusted-code-mitigations --mojo-platform-channel-handle=6392 /prefetch:1
Parent                     : System.Diagnostics.Process (chrome)
Company                    : Google LLC
CPU                        : 1.328125
ProductVersion             : 90.0.4430.19
Description                : Google Chrome
Product                    : Google Chrome
__NounName                 : Process
SafeHandle                 : Microsoft.Win32.SafeHandles.SafeProcessHandle
Handle                     : 4824
BasePriority               : 4
ExitCode                   :
HasExited                  : False
StartTime                  : 3/9/2021 8:07:50 PM
ExitTime                   :
MachineName                : .
MaxWorkingSet              : 1413120
MinWorkingSet              : 204800
Modules                    : {System.Diagnostics.ProcessModule (chrome.exe), System.Diagnostics.ProcessModule (ntdll.dll), System.Diagnostics.ProcessModule (KERNEL32.DLL), System.Diagnostics.ProcessModule (KERNELBASE.dll)…}
NonpagedSystemMemorySize64 : 15152
NonpagedSystemMemorySize   : 15152
PagedMemorySize64          : 24014848
PagedSystemMemorySize64    : 497784
PagedSystemMemorySize      : 497784
PeakPagedMemorySize64      : 34066432
PeakPagedMemorySize        : 34066432
PeakWorkingSet64           : 55562240
PeakWorkingSet             : 55562240
PeakVirtualMemorySize64    : 2315328487424
PeakVirtualMemorySize      : 341114880
PriorityBoostEnabled       : True
PrivateMemorySize64        : 24014848
ProcessName                : chrome
ProcessorAffinity          : 255
SessionId                  : 2
StartInfo                  :
Threads                    : {8912, 11924, 5364, 11744…}
VirtualMemorySize64        : 2311096541184
EnableRaisingEvents        : False
StandardInput              :
StandardOutput             :
StandardError              :
WorkingSet64               : 44044288
SynchronizingObject        :
MainModule                 : System.Diagnostics.ProcessModule (chrome.exe)
PrivilegedProcessorTime    : 00:00:00.3281250
UserProcessorTime          : 00:00:01
MainWindowHandle           : 0
MainWindowTitle            :
Responding                 : True
Site                       :
Container                  :

Name                       : chrome
Id                         : 15152
PriorityClass              : Normal
FileVersion                : 90.0.4430.19
HandleCount                : 284
WorkingSet                 : 100093952
PagedMemorySize            : 55312384
PrivateMemorySize          : 55312384
VirtualMemorySize          : 483598336
TotalProcessorTime         : 00:00:06.4531250
SI                         : 2
Handles                    : 284
VM                         : 2315470970880
WS                         : 100093952
PM                         : 55312384
NPM                        : 20864
Path                       : C:\Program Files\Google\Chrome Dev\Application\chrome.exe
CommandLine                : "C:\Program Files\Google\Chrome Dev\Application\chrome.exe" --type=renderer --field-trial-handle=1624,9494390279174207997,2118100447490828961,131072 --disable-databases --lang=en-US
                             --origin-trial-disabled-features=SecurePaymentConfirmation --device-scale-factor=1.15625 --num-raster-threads=4 --enable-main-frame-before-activation --renderer-client-id=59
                             --no-v8-untrusted-code-mitigations --mojo-platform-channel-handle=7768 /prefetch:1
Parent                     : System.Diagnostics.Process (chrome)
Company                    : Google LLC
CPU                        : 6.453125
ProductVersion             : 90.0.4430.19
Description                : Google Chrome
Product                    : Google Chrome
__NounName                 : Process
SafeHandle                 : Microsoft.Win32.SafeHandles.SafeProcessHandle
Handle                     : 3248
BasePriority               : 8
ExitCode                   :
HasExited                  : False
StartTime                  : 3/9/2021 8:11:46 PM
ExitTime                   :
MachineName                : .
MaxWorkingSet              : 1413120
MinWorkingSet              : 204800
Modules                    : {System.Diagnostics.ProcessModule (chrome.exe), System.Diagnostics.ProcessModule (ntdll.dll), System.Diagnostics.ProcessModule (KERNEL32.DLL), System.Diagnostics.ProcessModule (KERNELBASE.dll)…}
NonpagedSystemMemorySize64 : 20864
NonpagedSystemMemorySize   : 20864
PagedMemorySize64          : 55312384
PagedSystemMemorySize64    : 554424
PagedSystemMemorySize      : 554424
PeakPagedMemorySize64      : 150736896
PeakPagedMemorySize        : 150736896
PeakWorkingSet64           : 210989056
PeakWorkingSet             : 210989056
PeakVirtualMemorySize64    : 2319807651840
PeakVirtualMemorySize      : 525312000
PriorityBoostEnabled       : True
PrivateMemorySize64        : 55312384
ProcessName                : chrome
ProcessorAffinity          : 255
SessionId                  : 2
StartInfo                  :
Threads                    : {14420, 15700, 1448, 3520…}
VirtualMemorySize64        : 2315470970880
EnableRaisingEvents        : False
StandardInput              :
StandardOutput             :
StandardError              :
WorkingSet64               : 100093952
SynchronizingObject        :
MainModule                 : System.Diagnostics.ProcessModule (chrome.exe)
PrivilegedProcessorTime    : 00:00:00.7343750
UserProcessorTime          : 00:00:05.7187500
MainWindowHandle           : 0
MainWindowTitle            :
Responding                 : True
Site                       :
Container                  :

Name                       : chrome
Id                         : 15420
PriorityClass              : Idle
FileVersion                : 90.0.4430.19
HandleCount                : 208
WorkingSet                 : 22900736
PagedMemorySize            : 18153472
PrivateMemorySize          : 18153472
VirtualMemorySize          : 396161024
TotalProcessorTime         : 00:00:00.0937500
SI                         : 2
Handles                    : 208
VM                         : 2311088566272
WS                         : 22900736
PM                         : 18153472
NPM                        : 13520
Path                       : C:\Program Files\Google\Chrome Dev\Application\chrome.exe
CommandLine                : "C:\Program Files\Google\Chrome Dev\Application\chrome.exe" --type=renderer --field-trial-handle=1624,9494390279174207997,2118100447490828961,131072 --disable-databases --lang=en-US
                             --origin-trial-disabled-features=SecurePaymentConfirmation --device-scale-factor=1.15625 --num-raster-threads=4 --enable-main-frame-before-activation --renderer-client-id=60
                             --no-v8-untrusted-code-mitigations --mojo-platform-channel-handle=7720 /prefetch:1
Parent                     : System.Diagnostics.Process (chrome)
Company                    : Google LLC
CPU                        : 0.09375
ProductVersion             : 90.0.4430.19
Description                : Google Chrome
Product                    : Google Chrome
__NounName                 : Process
SafeHandle                 : Microsoft.Win32.SafeHandles.SafeProcessHandle
Handle                     : 5668
BasePriority               : 4
ExitCode                   :
HasExited                  : False
StartTime                  : 3/9/2021 8:12:34 PM
ExitTime                   :
MachineName                : .
MaxWorkingSet              : 1413120
MinWorkingSet              : 204800
Modules                    : {System.Diagnostics.ProcessModule (chrome.exe), System.Diagnostics.ProcessModule (ntdll.dll), System.Diagnostics.ProcessModule (KERNEL32.DLL), System.Diagnostics.ProcessModule (KERNELBASE.dll)…}
NonpagedSystemMemorySize64 : 13520
NonpagedSystemMemorySize   : 13520
PagedMemorySize64          : 18153472
PagedSystemMemorySize64    : 499104
PagedSystemMemorySize      : 499104
PeakPagedMemorySize64      : 18227200
PeakPagedMemorySize        : 18227200
PeakWorkingSet64           : 23191552
PeakWorkingSet             : 23191552
PeakVirtualMemorySize64    : 2315328487424
PeakVirtualMemorySize      : 341114880
PriorityBoostEnabled       : True
PrivateMemorySize64        : 18153472
ProcessName                : chrome
ProcessorAffinity          : 255
SessionId                  : 2
StartInfo                  :
Threads                    : {9520, 3256, 6704, 11944…}
VirtualMemorySize64        : 2311088566272
EnableRaisingEvents        : False
StandardInput              :
StandardOutput             :
StandardError              :
WorkingSet64               : 22900736
SynchronizingObject        :
MainModule                 : System.Diagnostics.ProcessModule (chrome.exe)
PrivilegedProcessorTime    : 00:00:00.0468750
UserProcessorTime          : 00:00:00.0468750
MainWindowHandle           : 0
MainWindowTitle            :
Responding                 : True
Site                       :
Container                  :

Name                       : chrome
Id                         : 15504
PriorityClass              : Idle
FileVersion                : 90.0.4430.19
HandleCount                : 262
WorkingSet                 : 14872576
PagedMemorySize            : 27742208
PrivateMemorySize          : 27742208
VirtualMemorySize          : 441139200
TotalProcessorTime         : 00:00:00.8593750
SI                         : 2
Handles                    : 262
VM                         : 2311133544448
WS                         : 14872576
PM                         : 27742208
NPM                        : 16376
Path                       : C:\Program Files\Google\Chrome Dev\Application\chrome.exe
CommandLine                : "C:\Program Files\Google\Chrome Dev\Application\chrome.exe" --type=renderer --field-trial-handle=1624,9494390279174207997,2118100447490828961,131072 --disable-databases --lang=en-US
                             --origin-trial-disabled-features=SecurePaymentConfirmation --device-scale-factor=1.15625 --num-raster-threads=4 --enable-main-frame-before-activation --renderer-client-id=17
                             --no-v8-untrusted-code-mitigations --mojo-platform-channel-handle=5936 /prefetch:1
Parent                     : System.Diagnostics.Process (chrome)
Company                    : Google LLC
CPU                        : 0.859375
ProductVersion             : 90.0.4430.19
Description                : Google Chrome
Product                    : Google Chrome
__NounName                 : Process
SafeHandle                 : Microsoft.Win32.SafeHandles.SafeProcessHandle
Handle                     : 4544
BasePriority               : 4
ExitCode                   :
HasExited                  : False
StartTime                  : 3/9/2021 7:47:50 PM
ExitTime                   :
MachineName                : .
MaxWorkingSet              : 1413120
MinWorkingSet              : 204800
Modules                    : {System.Diagnostics.ProcessModule (chrome.exe), System.Diagnostics.ProcessModule (ntdll.dll), System.Diagnostics.ProcessModule (KERNEL32.DLL), System.Diagnostics.ProcessModule (KERNELBASE.dll)…}
NonpagedSystemMemorySize64 : 16376
NonpagedSystemMemorySize   : 16376
PagedMemorySize64          : 27742208
PagedSystemMemorySize64    : 508280
PagedSystemMemorySize      : 508280
PeakPagedMemorySize64      : 50372608
PeakPagedMemorySize        : 50372608
PeakWorkingSet64           : 79515648
PeakWorkingSet             : 79515648
PeakVirtualMemorySize64    : 2315345321984
PeakVirtualMemorySize      : 357949440
PriorityBoostEnabled       : True
PrivateMemorySize64        : 27742208
ProcessName                : chrome
ProcessorAffinity          : 255
SessionId                  : 2
StartInfo                  :
Threads                    : {14088, 13100, 15560, 13208…}
VirtualMemorySize64        : 2311133544448
EnableRaisingEvents        : False
StandardInput              :
StandardOutput             :
StandardError              :
WorkingSet64               : 14872576
SynchronizingObject        :
MainModule                 : System.Diagnostics.ProcessModule (chrome.exe)
PrivilegedProcessorTime    : 00:00:00.2031250
UserProcessorTime          : 00:00:00.6562500
MainWindowHandle           : 0
MainWindowTitle            :
Responding                 : True
Site                       :
Container                  :

Name                       : chrome
Id                         : 16284
PriorityClass              : Idle
FileVersion                : 90.0.4430.19
HandleCount                : 228
WorkingSet                 : 33853440
PagedMemorySize            : 21180416
PrivateMemorySize          : 21180416
VirtualMemorySize          : 403996672
TotalProcessorTime         : 00:00:00.1875000
SI                         : 2
Handles                    : 228
VM                         : 2311096401920
WS                         : 33853440
PM                         : 21180416
NPM                        : 14744
Path                       : C:\Program Files\Google\Chrome Dev\Application\chrome.exe
CommandLine                : "C:\Program Files\Google\Chrome Dev\Application\chrome.exe" --type=renderer --field-trial-handle=1624,9494390279174207997,2118100447490828961,131072 --disable-databases --lang=en-US
                             --origin-trial-disabled-features=SecurePaymentConfirmation --device-scale-factor=1.15625 --num-raster-threads=4 --enable-main-frame-before-activation --renderer-client-id=48
                             --no-v8-untrusted-code-mitigations --mojo-platform-channel-handle=1500 /prefetch:1
Parent                     : System.Diagnostics.Process (chrome)
Company                    : Google LLC
CPU                        : 0.1875
ProductVersion             : 90.0.4430.19
Description                : Google Chrome
Product                    : Google Chrome
__NounName                 : Process
SafeHandle                 : Microsoft.Win32.SafeHandles.SafeProcessHandle
Handle                     : 4988
BasePriority               : 4
ExitCode                   :
HasExited                  : False
StartTime                  : 3/9/2021 8:07:29 PM
ExitTime                   :
MachineName                : .
MaxWorkingSet              : 1413120
MinWorkingSet              : 204800
Modules                    : {System.Diagnostics.ProcessModule (chrome.exe), System.Diagnostics.ProcessModule (ntdll.dll), System.Diagnostics.ProcessModule (KERNEL32.DLL), System.Diagnostics.ProcessModule (KERNELBASE.dll)…}
NonpagedSystemMemorySize64 : 14744
NonpagedSystemMemorySize   : 14744
PagedMemorySize64          : 21180416
PagedSystemMemorySize64    : 477032
PagedSystemMemorySize      : 477032
PeakPagedMemorySize64      : 23470080
PeakPagedMemorySize        : 23470080
PeakWorkingSet64           : 40706048
PeakWorkingSet             : 40706048
PeakVirtualMemorySize64    : 2315328487424
PeakVirtualMemorySize      : 341114880
PriorityBoostEnabled       : True
PrivateMemorySize64        : 21180416
ProcessName                : chrome
ProcessorAffinity          : 255
SessionId                  : 2
StartInfo                  :
Threads                    : {11688, 13700, 4288, 3356…}
VirtualMemorySize64        : 2311096401920
EnableRaisingEvents        : False
StandardInput              :
StandardOutput             :
StandardError              :
WorkingSet64               : 33853440
SynchronizingObject        :
MainModule                 : System.Diagnostics.ProcessModule (chrome.exe)
PrivilegedProcessorTime    : 00:00:00.0468750
UserProcessorTime          : 00:00:00.1406250
MainWindowHandle           : 0
MainWindowTitle            :
Responding                 : True
Site                       :
Container                  :


PS C:\Program Files\Notepad++>
PS C:\Program Files\Notepad++> ssh
usage: ssh [-46AaCfGgKkMNnqsTtVvXxYy] [-B bind_interface]
           [-b bind_address] [-c cipher_spec] [-D [bind_address:]port]
           [-E log_file] [-e escape_char] [-F configfile] [-I pkcs11]
           [-i identity_file] [-J [user@]host[:port]] [-L address]
           [-l login_name] [-m mac_spec] [-O ctl_cmd] [-o option] [-p port]
           [-Q query_option] [-R address] [-S ctl_path] [-W host:port]
           [-w local_tun[:remote_tun]] destination [command]
PS C:\Program Files\Notepad++> ssh -q https://cs50.harvard.edu/SPACES:8080
PS C:\Program Files\Notepad++> ssh -q https://cs50.harvard.edu/SPACES
PS C:\Program Files\Notepad++> ssh -q https://www.cs50.harvard.edu/SPACES
PS C:\Program Files\Notepad++> ls

    Directory: C:\Program Files\Notepad++

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d----            3/8/2021  7:29 PM                autoCompletion
d----           2/27/2021  2:15 PM                localization
d----           2/27/2021  2:13 PM                plugins
d----            3/6/2021  1:24 AM                themes
d----           2/27/2021  2:13 PM                updater
-a---          10/31/2020  2:19 PM           2096 change.log
-a---            1/3/2020  4:55 AM           3535 contextMenu.xml
-a---           2/23/2020  5:00 PM          65305 functionList.xml
-a---          10/15/2020  3:45 PM         344199 langs.model.xml
-a---           8/27/2020  1:25 PM          15776 LICENSE
-a---           11/1/2020  7:21 PM        3584656 notepad++.exe
-a---           11/1/2020  7:21 PM         230032 NppShell_06.dll
-a---            1/3/2020  4:54 AM           1526 readme.txt
-a---           11/1/2020  7:21 PM        1804944 SciLexer.dll
-a---           12/2/2019  9:24 PM           1801 shortcuts.xml
-a---          10/15/2020  3:45 PM         170624 stylers.model.xml
-a---           2/27/2021  2:18 PM         265238 uninstall.exe

PS C:\Program Files\Notepad++> cd C:\Memory\WEBROOT\php\
PS C:\Memory\WEBROOT\php> ls

    Directory: C:\Memory\WEBROOT\php

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d----            3/6/2021  2:18 PM                600
d----           1/31/2021  3:07 PM                c.BACKUP
d----           1/31/2021  9:37 PM                CAMERA
d----           1/31/2021 11:08 PM                CSS
d----            2/4/2021 10:07 PM                DEV__DEBUG
d----            2/4/2021 10:29 PM                DST
d----            2/4/2021 10:22 PM                HOME
d----           2/28/2021  3:14 AM                New folder
d----           2/18/2021  8:12 AM                php
d----           1/31/2021 12:12 PM                SESSIONS
-a---           1/31/2021  1:27 PM           7586 HEADERS.php
-a---           1/31/2021 10:13 PM            196 index.html
-a---           1/31/2021  3:29 PM           1068 MATRIX_GOOGLE.html
-a---           1/31/2021  8:42 AM            195 server.php

PS C:\Memory\WEBROOT\php> h

  Id     Duration CommandLine
  --     -------- -----------
   1        0.273 https://login.live-int.com/ManageLoginKeys.srf
   2        0.048 Fhttps://login.live-int.com/ManageLoginKeys.srf
   3        0.946 CURL https://login.live-int.com/ManageLoginKeys.srf
   4        0.106 CAL
   5        0.059 CURL -  https://login.live-int.com/ManageLoginKeys.srf
   6        0.106 Get-Process PWSH
   7        0.030 Get-Process PWSH || KILL
   8        0.049 Get-Process PWSH |KILL
   9        0.057 Get-Process PWSH
  10        0.080 EXIT /?
  11        0.883 HELP EXI
  12        0.057 Exit-PSHostProcess -Verbose:$true -InformationAction:(START PWSH -FORCE:$TRUE)
  13        0.112 Exit-PSHostProcess -Verbose:$true -InformationAction:(START PWSH)
  14        0.012 Exit-PSHostProcess -Verbose
  15        0.008 Exit-PSHostProcess
  16        0.002 Exit-PSHostProcess
  17        0.002 Exit-PSHostProcess
  18        0.001 Exit-PSHostProcess
  19        0.002 Exit-PSHostProcess
  20        0.046 Exit-PSHostProcess Exit-PSHostProcess Exit-PSHostProcess Exit-PSHostProcess Exit-PSHostProcess Exit-PSHostProcess Exit-PSHostProcess Exit-PSHostProcess Exit-PSHostProcess Exit-PSHostProcess Exit-PSHostProcess
  21        0.000 ||
  22        0.003 Exit-PSHostProcess
  23        0.052 Exit-PSHostProcess PWSH
  24        0.033 Exit-PSHostProcess PWSH
  25        0.047 PS PWSH
  26        0.033 START PY
  27        0.031 START PY
  28        1.073 Get-M365DSCAllResources
  29        0.078 Get-Module
  30        0.038 Get-Module
  31        0.049 Get-Module
  32        0.038 Get-Module
  33        3.805 AzureADPreview\Add-AzureADAdministrativeUnitMember
  34        0.063 AzureADPreview\Get-AzureADAdministrativeUnit
  35       43.877 AzureADPreview\Connect-AzureAD
  36        0.052 h
  37       13.248 Add-Type -ReferencedAssemblies:System.Security.Cryptography.SHA256Cng
  38        0.015 ([System.Reflection.Metadata.TypeDefinition])
  39     1:14.493 AzureADPreview\Get-AzureADServicePrincipalOAuth2PermissionGrant
  40        0.039 AzureADPreview\Add-AzureADServicePrincipalPolicy ([System.Runtime.Serialization.ObjectIDGenerator])
  41        0.033 AzureADPreview\Add-AzureADServicePrincipalPolicy :([System.Runtime.Serialization.ObjectIDGenerator])
  42        0.038 AzureADPreview\Add-AzureADServicePrincipalPolicy:([System.Runtime.Serialization.ObjectIDGenerator])
  43     1:40.816 AzureADPreview\Add-AzureADServicePrincipalPolicy ||([System.Runtime.Serialization.ObjectIDGenerator])
  44        0.011 ([System.Runtime.Serialization.ObjectIDGenerator]).id
  45        0.029 explorer.exe
  46        0.029 ([System.Runtime.Serialization.ObjectIDGenerator]).GUID
  47     2:19.619 AzureADPreview\Add-AzureADServicePrincipalPolicy ||([System.Runtime.Serialization.ObjectIDGenerator])
  48        1.474 AzureADPreview\Add-AzureADServicePrincipalPolicy ||([System.Runtime.Serialization.ObjectIDGenerator])
  49        5.892 AzureADPreview\Add-AzureADServicePrincipalPolicy ||([System.Runtime.Serialization.ObjectIDGenerator]) | Format-Custom
  50        6.578 AzureADPreview\Add-AzureADServicePrincipalPolicy ||([System.Runtime.Serialization.ObjectIDGenerator])
  51       15.221 AzureADPreview\Add-AzureADServicePrincipalPolicy ||([System.Runtime.Serialization.ObjectIDGenerator])
  52        0.000 AzureADPreview\Add-AzureADServicePrincipalPolicy |([System.Runtime.Serialization.ObjectIDGenerator])
  53        0.042 AzureADPreview\Add-AzureADMSServicePrincipalDelegatedPermissionClassification([System.Runtime.Serialization.ObjectIDGenerator])
  54       26.267 AzureADPreview\Add-AzureADMSServicePrincipalDelegatedPermissionClassification -PermissionName:.\autoCompletion\
  55       13.215 AzureADPreview\Add-AzureADMSServicePrincipalDelegatedPermissionClassification -PermissionName:.\autoCompletion\
  56        1.887 Add-AzureADMSApplicationOwner || AzureADPreview\Add-AzureADMSServicePrincipalDelegatedPermissionClassification -PermissionName:.\autoCompletion\ -ServicePrincipalId:bigint -Classification:Low -PermissionId:'N,U'
  57     1:21.105 Connect-AzureAD || Add-AzureADMSApplicationOwner || AzureADPreview\Add-AzureADMSServicePrincipalDelegatedPermissionClassification -PermissionName:.\autoCompletion\ -ServicePrincipalId:bigint -Classification:Low -Permi…
  58        2.767 Add-AzureADMSApplicationOwner | AzureADPreview\Add-AzureADMSServicePrincipalDelegatedPermissionClassification -PermissionName:.\autoCompletion\ -ServicePrincipalId:bigint -Classification:Low -PermissionId:'N,U'
  59        2.194 Add-AzureADMSApplicationOwner -ObjectId:.\SciLexer.dll | AzureADPreview\Add-AzureADMSServicePrincipalDelegatedPermissionClassification -PermissionName:.\autoCompletion\ -ServicePrincipalId:bigint -Classification:Low -…
  60        0.036 Add-AzureADMSApplicationOwner -ObjectId:SciLexer.dll  -RefObjectId:LICENSE | AzureADPreview\Add-AzureADMSServicePrincipalDelegatedPermissionClassification -PermissionName:.\autoCompletion\ -ServicePrincipalId:bigint -…
  61        0.043 cd r:\
  62        0.144 ps chrome
  63        0.121 ps chrome | Format-List **]
  64        7.420 ps chrome | Format-List **
  65        0.051 ssh
  66        0.048 ssh -q https://cs50.harvard.edu/SPACES:8080
  67        0.046 ssh -q https://cs50.harvard.edu/SPACES
  68        0.052 ssh -q https://www.cs50.harvard.edu/SPACES
  69        0.077 ls
  70        0.010 cd C:\Memory\WEBROOT\php\
  71        0.070 ls

PS C:\Memory\WEBROOT\php> ps

 NPM(K)    PM(M)      WS(M)     CPU(s)      Id  SI ProcessName
 ------    -----      -----     ------      --  -- -----------
     10     1.42       6.09       0.02   13164   0 alg
      9     1.56       5.81       0.00    2884   0 AppHelperCap
     33    24.55      40.38       1.95   13296   2 ApplicationFrameHost
     13    12.35      21.43       2.36    7152   0 audiodg
     19     9.36      32.64       0.19   11928   2 BOAudioControl
     41    32.14      29.27       6.00    2400   2 chrome
     18    32.11      28.80       0.78    4708   2 chrome
     14    19.67      35.71       0.09    5100   2 chrome
     17    14.40      10.57       0.17    8260   2 chrome
     13    14.19       4.93       0.25    8868   2 chrome
     32   262.75     201.32      48.44    9248   2 chrome
     79   149.41     141.29      64.23    9756   2 chrome
     21    42.74      36.42       3.03   13620   2 chrome
     16    24.54      43.99       1.33   13912   2 chrome
     16    21.41      16.23       0.83   14168   2 chrome
     13    17.30      21.84       0.11   14648   2 chrome
     19    44.93      38.95       9.23   14788   2 chrome
      9     6.01       1.51       0.11   15652   2 chrome
     20    97.08     142.86       5.06   15864   2 chrome
      7     1.62       8.25       0.05   12348   2 CompPkgSrv
      8     2.88       6.41       0.02    2796   2 conhost
     16    11.18      14.73      20.53    3480   2 conhost
      7     6.07       4.13       0.00    5184   0 conhost
     12     6.98      11.58       0.53    8652   2 conhost
     14     7.42      15.52      35.31   10236   2 conhost
     16    13.90      16.23      14.34   12484   2 conhost
     27     1.94       4.42       1.77     704   0 csrss
     23     2.59       7.06      53.19    4996   2 csrss
     20    40.15      35.73      49.89    2352   2 ctfmon
     20     5.46      13.86       0.45    2892   0 dasHost
     23     6.37      13.76       1.70   10304   2 dllhost
      7     1.32       6.50       0.00   13840   2 dllhost
    147   218.57     242.10      29.78   11432   2 dotnet
     60   123.65     114.75     429.14    6092   2 dwm
      7     1.64       4.95       0.03    5744   0 esif_uf
    117   145.78     224.31      79.30    2244   2 explorer
     50    84.83     121.93     147.41   11216   2 explorer
      5     1.25       2.27       0.03    1036   0 fontdrvhost
     10     5.12      12.85       5.97    5884   2 fontdrvhost
      9     1.62       1.03       0.03   10764   0 GoogleCrashHandler64
     17     3.73      21.20       0.23   12996   2 HelpPane
      6     1.03       4.38       0.06    5612   0 ibtsiva
      0     0.06       0.01       0.00       0   0 Idle
     10     2.07       7.91       0.09    2488   0 igfxCUIServiceN
     20     5.38      18.19       0.91    6072   2 igfxEMN
     23    28.52      16.04       1.05    5716   0 IntelAudioService
      7     1.16       4.68       0.03    1888   0 IntelCpHDCPSvc
      7     1.06       4.75       0.03    6352   0 jhi_service
      6     0.97       2.47       0.14     980   0 LsaIso
     29    11.30      24.61      18.73     988   0 lsass
      0     0.95     143.00      59.55    4292   0 Memory Compression
     19    31.43      19.77       2.30   15272   0 MoUsoCoreWorker
     83   299.77     200.95   1,342.84    6000   0 MsMpEng
     13     2.56       9.39       0.20    2908   0 NetworkCap
     20     8.02      12.65       3.55   10980   0 NisSrv
     14     2.90      16.01       0.31     888   2 notepad
     14     2.96      16.34       0.94    3728   2 notepad
     14     2.90      17.37       0.70    8688   2 notepad
     12     2.56      14.02       1.45    8948   2 notepad
     15     4.03      20.53       3.55   10144   2 notepad
     14     3.05      16.25       0.69   10536   2 notepad
     14     2.91      15.86       0.33   13176   2 notepad
     14     2.87      15.94       0.48   14560   2 notepad
     12     2.45      12.89       0.75   15280   2 notepad
     47   120.09      73.52     237.02    9672   2 notepad++
     41    30.77      25.53       0.39    5584   0 OneApp.IGCC.WinService
     49    48.38      90.41       4.62   14708   2 OpenWith
     31    55.11       1.47       0.86    8964   2 PaintStudio.View
    256   212.15     170.02       7.06    6272   2 powershell
     27   133.71      47.66       3.22   14884   2 powershell
     27    23.49      15.26       0.16    6008   0 PresentationFontCache
     25    11.14      46.32       2.98   14452   2 prevhost
    142   354.64     256.77     127.34    5872   2 pwsh
      9     1.50       5.96       0.03    4028   2 py
      7     3.32       5.23       0.02    5088   2 python
     10     6.11      70.59       0.92     132   0 Registry
      8     1.55       6.12       0.02    5808   0 RstMwService
     13     4.29      10.04       0.67    5788   0 RtkAudUService64
     14     4.33       3.75       0.44   11676   2 RtkAudUService64
      9     3.78       9.62       0.05    3004   2 RuntimeBroker
     14     3.00      20.64       0.09    3524   2 RuntimeBroker
      8     1.67       7.66       0.00    7880   2 RuntimeBroker
     29    11.55      40.58      11.77    8532   2 RuntimeBroker
     17     6.12      25.73       2.23    8988   2 RuntimeBroker
     19     6.41      25.69       2.83    9776   2 RuntimeBroker
     13     5.12      18.73       0.27   12576   2 RuntimeBroker
     12     2.59      12.86       0.05   12824   2 RuntimeBroker
      7     1.75       6.68       0.09   14232   2 RuntimeBroker
    100   133.34      97.47      10.22    7040   2 SearchApp
     76   102.74     176.29       5.83   15608   2 SearchApp
     34    18.16      20.39      51.45   13356   0 SearchIndexer
     10     3.10       9.01       0.58    5784   0 SECOMN64
      0     0.18      35.48       0.00      72   0 Secure System
     12     2.81      11.21       0.19    4964   0 SecurityHealthService
     12     6.54       9.20      17.92     940   0 services
     23     7.02       6.17       1.31   12356   2 SettingSyncHost
      7     7.66       7.89       3.05   10524   0 SgrmBroker
     18     7.45      28.68       8.52    4688   2 sihost
     23     7.92      22.77       0.12   15856   2 smartscreen
      3     1.05       1.10       0.22     460   0 smss
     23     5.68      14.65       0.61    2556   0 spoolsv
     28    17.35      60.39       1.12   11612   2 StartMenuExperienceHost
     25    15.95      33.59     162.30     488   0 svchost
      8     1.61       5.24       0.00     692   0 svchost
     15     4.12      12.22       0.14     956   0 svchost
     20    12.33      18.90     137.92    1160   0 svchost
     11     3.16      10.18       6.62    1216   0 svchost
     15    14.73      15.41       3.62    1308   0 svchost
     19     5.09      10.88       1.19    1436   0 svchost
     13     1.79       6.66       0.08    1480   0 svchost
      9     1.75       9.63       0.22    1492   0 svchost
     21     2.91      10.46       0.11    1512   0 svchost
      9     1.10       4.80       0.02    1532   0 svchost
     13     2.11       7.85       0.98    1580   0 svchost
     15     3.61      13.11       2.05    1612   0 svchost
     13     2.54       9.21       1.23    1656   0 svchost
      9     2.05      10.07       0.11    1680   0 svchost
      7     1.70       5.75       1.53    1764   0 svchost
     17     6.00      14.21       1.80    1780   0 svchost
     18    10.89      17.68       4.56    1900   0 svchost
     10     2.07       7.65       0.08    1908   0 svchost
     12     2.04       5.82       0.08    1964   0 svchost
      9     2.54       7.51       4.12    1972   0 svchost
      9     1.83       7.22       3.42    2100   0 svchost
     10     2.99       9.86       3.83    2144   0 svchost
     12     1.94       7.15       0.09    2220   0 svchost
      9     1.61       6.86       0.06    2284   0 svchost
      8     1.40       6.11       0.03    2316   0 svchost
     15     4.75      10.70       1.23    2344   0 svchost
     25     5.08       8.01       0.78    2448   0 svchost
      9     1.66       6.81       0.16    2460   0 svchost
     10     2.14       6.73       1.14    2712   0 svchost
      9     1.68       7.97       0.00    2752   2 svchost
     12     2.46       9.88       0.42    2852   0 svchost
      9     1.55       6.23       0.06    2864   0 svchost
     11     2.58       9.98       1.28    2936   0 svchost
     25    13.32      19.54      32.00    3060   0 svchost
     31    15.36      18.72      13.75    3108   0 svchost
     11     2.18       7.40     354.09    3168   0 svchost
     31     3.80      11.97       3.75    3228   0 svchost
      8     1.58       7.21       0.06    3268   2 svchost
     14     2.29       8.69       0.23    3296   0 svchost
     12     2.98       8.69       5.11    3340   0 svchost
     10     2.05       7.29      17.97    3540   0 svchost
     20     7.53      11.73       0.09    3552   0 svchost
     15     9.89      17.44      12.58    3628   0 svchost
     17     2.40       6.81       0.75    3820   0 svchost
     12     2.98      12.60      26.23    4160   0 svchost
      7     1.29       5.24       0.47    4164   0 svchost
     11     2.57       8.56       3.73    4176   0 svchost
      9     1.68       7.81       0.41    4220   2 svchost
      9     2.01       7.11       0.78    4240   0 svchost
      9     1.68       7.55       0.47    4248   0 svchost
      7     1.34       5.99       0.02    4384   0 svchost
     14     3.68      14.06       5.17    4488   0 svchost
     11     1.82       6.04       0.17    4648   0 svchost
     15     4.17       9.00       4.42    4656   0 svchost
     17     2.79       8.89       2.52    4664   0 svchost
     20    13.60      32.35      45.38    4672   2 svchost
     10     2.14       7.00       1.59    4816   0 svchost
     22     7.40      18.88      12.19    4892   0 svchost
     11     2.43       7.54       1.31    4940   0 svchost
     12     2.17      11.03       0.08    4988   0 svchost
     10     2.27      12.44       0.05    5144   0 svchost
     32    19.16      14.75      52.27    5212   0 svchost
     13     2.79      11.53       2.08    5500   0 svchost
      7     1.29       5.14       0.02    5552   0 svchost
      8     1.58       6.78       0.03    5560   0 svchost
     13     2.60       7.28       0.25    5568   0 svchost
     25    23.37      30.68       6.30    5576   0 svchost
     25    38.41      42.73     112.83    5604   0 svchost
     17     2.81       9.33       0.36    5664   0 svchost
     23    25.80      40.00       3.16    5740   2 svchost
      9     1.53       5.83       0.03    5800   0 svchost
     12     2.52       8.54       0.94    5908   0 svchost
      7     1.21       4.94       0.05    5976   0 svchost
     18     4.38      18.50       0.98    6040   0 svchost
     13     2.33       6.55       0.03    6164   0 svchost
      7     1.28       5.91       0.08    6448   0 svchost
     15     2.00       7.26       0.03    6756   0 svchost
     21     3.57      11.84       0.14    6780   0 svchost
      5     0.95       4.19       0.00    6996   0 svchost
     24     5.00      17.53       0.31    7036   2 svchost
     12     3.95      15.75       5.08    7356   0 svchost
     17     4.56      15.52       8.44    7432   0 svchost
     24     5.46      19.09       0.47    7624   0 svchost
     13     4.89      10.03       0.39    7628   0 svchost
     12     2.85      10.76       3.52    7764   0 svchost
     12     2.63      10.87       0.06    7840   0 svchost
     23     8.64      33.39       1.92    8020   2 svchost
      8     2.46       8.40       0.03    8052   0 svchost
     84    34.33      33.22     312.09    8112   0 svchost
      8     1.56       6.73       0.02    8136   0 svchost
      8     1.42       6.09       0.06    9916   0 svchost
     13     2.32      10.84       0.33   10092   0 svchost
     11     2.71       8.67       1.36   10108   0 svchost
     11     2.53       9.69       0.09   10164   0 svchost
     48    64.73       9.42       0.38   10456   0 svchost
     10     1.93       7.55       0.08   10924   0 svchost
     12     2.58       9.36       0.28   10956   0 svchost
     19     4.84      19.45       0.25   10988   0 svchost
     15     2.84       8.22       0.41   11048   0 svchost
      8     1.46       5.87       0.02   11416   0 svchost
     10     2.07       8.68       0.03   12056   0 svchost
      8     1.63       7.38       0.00   14672   0 svchost
   2130     8.03      20.45      56.72    8620   2 SynTPEnh
     12     3.30       8.00       0.08    3772   0 SynTPEnhService
     16     4.82      11.52       0.31    2900   0 SysInfoCap
      0     0.19       0.13     730.05       4   0 System
     34    21.00       1.43       0.66    8372   2 SystemSettings
     14     2.97      13.47       0.06    8352   2 SystemSettingsAdminFlows
     16     4.02      16.99       8.50   12416   2 TabTip
     40     9.96      20.12       4.31    9052   2 taskhostw
     39    59.04      78.48     457.77   12712   2 Taskmgr
     26    19.05      61.32       2.14   10136   2 TextInputHost
     46    54.80      53.70       5.02    2916   0 TouchpointAnalyticsClientService
      7     1.55       6.32       0.23    4000   0 unsecapp
     31    18.07       1.45       0.22    5544   2 Video.UI
     18     4.63      14.74       0.61    5988   0 WebManagement
     11     1.39       5.79       0.05     796   0 wininit
     14     3.14      10.79       0.36    5644   2 winlogon
     65    46.76       1.46       1.42    8600   2 WinStore.App
      7     1.14       5.18       0.03    5136   0 wlanext
      5     0.73       3.47       0.06    6048   0 wlms
     12     2.98       8.41       0.66    3532   0 WmiPrvSE
     15     9.38      14.98      13.61    3904   0 WmiPrvSE
     15    10.20       9.78      25.81    1092   0 WUDFHost
     17     9.11      15.88       0.89    1312   0 WUDFHost
     39    23.93       1.49       0.45   10656   2 YourPhone

PS C:\Memory\WEBROOT\php> ps Video.UI

 NPM(K)    PM(M)      WS(M)     CPU(s)      Id  SI ProcessName
 ------    -----      -----     ------      --  -- -----------
     31    18.07       1.45       0.22    5544   2 Video.UI

PS C:\Memory\WEBROOT\php> ps Video.UI **
Get-Process: A positional parameter cannot be found that accepts argument '**'.
PS C:\Memory\WEBROOT\php> ps Video.UI -Module:$false

 NPM(K)    PM(M)      WS(M)     CPU(s)      Id  SI ProcessName
 ------    -----      -----     ------      --  -- -----------
     31    18.07       1.45       0.22    5544   2 Video.UI

PS C:\Memory\WEBROOT\php> ps Video.UI -Module:$
Get-Process: Cannot convert 'System.String' to the type 'System.Management.Automation.SwitchParameter' required by parameter 'Module'.
PS C:\Memory\WEBROOT\php> ps Video.UI -Module:$switch{}
Get-Process: A positional parameter cannot be found that accepts argument ''.
PS C:\Memory\WEBROOT\php> ps Video.UI -Module:$switch{9}
Get-Process: A positional parameter cannot be found that accepts argument '9'.
PS C:\Memory\WEBROOT\php> netstat

Active Connections

  Proto  Local Address          Foreign Address        State
  TCP    127.0.0.1:445          captive0:65100         ESTABLISHED
  TCP    127.0.0.1:65100        captive0:microsoft-ds  ESTABLISHED
  TCP    192.168.1.72:49710     52.242.211.89:https    ESTABLISHED
  TCP    192.168.1.72:50890     a23-199-20-146:https   ESTABLISHED
  TCP    192.168.1.72:50894     151.101.1.108:https    ESTABLISHED
  TCP    192.168.1.72:50901     server-54-230-226-52:https  CLOSE_WAIT
  TCP    192.168.1.72:50929     40OnnRokuTV:8060       CLOSE_WAIT
  TCP    192.168.1.72:50930     43onnRokuTV:8060       CLOSE_WAIT
  TCP    192.168.1.72:50931     Livingroom:8060        CLOSE_WAIT
  TCP    192.168.1.72:50935     183:https              TIME_WAIT
  TCP    192.168.1.72:50936     183:https              ESTABLISHED
  TCP    192.168.1.72:50937     194:https              ESTABLISHED
  TCP    192.168.1.72:50957     20.44.17.0:https       ESTABLISHED
  TCP    [::1]:445              captive0:50425         ESTABLISHED
  TCP    [::1]:50425            captive0:microsoft-ds  ESTABLISHED
  TCP    [::1]:51109            captive0:wsd           TIME_WAIT
  TCP    [::1]:51111            captive0:wsd           TIME_WAIT
  TCP    [::1]:51112            captive0:wsd           TIME_WAIT
  TCP    [::1]:51116            captive0:wsd           TIME_WAIT
  TCP    [::1]:51138            captive0:wsd           TIME_WAIT
  TCP    [::1]:51186            captive0:9229          SYN_SENT
  TCP    [2600:1702:1fb0:ea40:14f9:7b98:f258:10db]:51070  dns:https              TIME_WAIT
  TCP    [2600:1702:1fb0:ea40:14f9:7b98:f258:10db]:51071  [2607:f8b0:4002:c10::5e]:https  TIME_WAIT
  TCP    [2600:1702:1fb0:ea40:14f9:7b98:f258:10db]:51184  atl14s91-in-x04:https  ESTABLISHED
PS C:\Memory\WEBROOT\php> "WIZ_global_data.OewCAd.replaceAll(utlusr)"^C
PS C:\Memory\WEBROOT\php> ^C
PS C:\Memory\WEBROOT\php> ^C
PS C:\Memory\WEBROOT\php> curl WIZ_global_data.OewCAd.replaceAll(utlusr)
utlusr: The term 'utlusr' is not recognized as a name of a cmdlet, function, script file, or executable program.
Check the spelling of the name, or if a path was included, verify that the path is correct and try again.
PS C:\Memory\WEBROOT\php> "WIZ_global_data.OewCAd.replaceAll(utlusr)"
WIZ_global_data.OewCAd.replaceAll(utlusr)
PS C:\Memory\WEBROOT\php> ls

    Directory: C:\Memory\WEBROOT\php

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d----            3/6/2021  2:18 PM                600
d----           1/31/2021  3:07 PM                c.BACKUP
d----           1/31/2021  9:37 PM                CAMERA
d----           1/31/2021 11:08 PM                CSS
d----            2/4/2021 10:07 PM                DEV__DEBUG
d----            2/4/2021 10:29 PM                DST
d----            2/4/2021 10:22 PM                HOME
d----           2/28/2021  3:14 AM                New folder
d----           2/18/2021  8:12 AM                php
d----           1/31/2021 12:12 PM                SESSIONS
-a---           1/31/2021  1:27 PM           7586 HEADERS.php
-a---           1/31/2021 10:13 PM            196 index.html
-a---           1/31/2021  3:29 PM           1068 MATRIX_GOOGLE.html
-a---           1/31/2021  8:42 AM            195 server.php

PS C:\Memory\WEBROOT\php> h

  Id     Duration CommandLine
  --     -------- -----------
   1        0.273 https://login.live-int.com/ManageLoginKeys.srf
   2        0.048 Fhttps://login.live-int.com/ManageLoginKeys.srf
   3        0.946 CURL https://login.live-int.com/ManageLoginKeys.srf
   4        0.106 CAL
   5        0.059 CURL -  https://login.live-int.com/ManageLoginKeys.srf
   6        0.106 Get-Process PWSH
   7        0.030 Get-Process PWSH || KILL
   8        0.049 Get-Process PWSH |KILL
   9        0.057 Get-Process PWSH
  10        0.080 EXIT /?
  11        0.883 HELP EXI
  12        0.057 Exit-PSHostProcess -Verbose:$true -InformationAction:(START PWSH -FORCE:$TRUE)
  13        0.112 Exit-PSHostProcess -Verbose:$true -InformationAction:(START PWSH)
  14        0.012 Exit-PSHostProcess -Verbose
  15        0.008 Exit-PSHostProcess
  16        0.002 Exit-PSHostProcess
  17        0.002 Exit-PSHostProcess
  18        0.001 Exit-PSHostProcess
  19        0.002 Exit-PSHostProcess
  20        0.046 Exit-PSHostProcess Exit-PSHostProcess Exit-PSHostProcess Exit-PSHostProcess Exit-PSHostProcess Exit-PSHostProcess Exit-PSHostProcess Exit-PSHostProcess Exit-PSHostProcess Exit-PSHostProcess Exit-PSHostProcess
  21        0.000 ||
  22        0.003 Exit-PSHostProcess
  23        0.052 Exit-PSHostProcess PWSH
  24        0.033 Exit-PSHostProcess PWSH
  25        0.047 PS PWSH
  26        0.033 START PY
  27        0.031 START PY
  28        1.073 Get-M365DSCAllResources
  29        0.078 Get-Module
  30        0.038 Get-Module
  31        0.049 Get-Module
  32        0.038 Get-Module
  33        3.805 AzureADPreview\Add-AzureADAdministrativeUnitMember
  34        0.063 AzureADPreview\Get-AzureADAdministrativeUnit
  35       43.877 AzureADPreview\Connect-AzureAD
  36        0.052 h
  37       13.248 Add-Type -ReferencedAssemblies:System.Security.Cryptography.SHA256Cng
  38        0.015 ([System.Reflection.Metadata.TypeDefinition])
  39     1:14.493 AzureADPreview\Get-AzureADServicePrincipalOAuth2PermissionGrant
  40        0.039 AzureADPreview\Add-AzureADServicePrincipalPolicy ([System.Runtime.Serialization.ObjectIDGenerator])
  41        0.033 AzureADPreview\Add-AzureADServicePrincipalPolicy :([System.Runtime.Serialization.ObjectIDGenerator])
  42        0.038 AzureADPreview\Add-AzureADServicePrincipalPolicy:([System.Runtime.Serialization.ObjectIDGenerator])
  43     1:40.816 AzureADPreview\Add-AzureADServicePrincipalPolicy ||([System.Runtime.Serialization.ObjectIDGenerator])
  44        0.011 ([System.Runtime.Serialization.ObjectIDGenerator]).id
  45        0.029 explorer.exe
  46        0.029 ([System.Runtime.Serialization.ObjectIDGenerator]).GUID
  47     2:19.619 AzureADPreview\Add-AzureADServicePrincipalPolicy ||([System.Runtime.Serialization.ObjectIDGenerator])
  48        1.474 AzureADPreview\Add-AzureADServicePrincipalPolicy ||([System.Runtime.Serialization.ObjectIDGenerator])
  49        5.892 AzureADPreview\Add-AzureADServicePrincipalPolicy ||([System.Runtime.Serialization.ObjectIDGenerator]) | Format-Custom
  50        6.578 AzureADPreview\Add-AzureADServicePrincipalPolicy ||([System.Runtime.Serialization.ObjectIDGenerator])
  51       15.221 AzureADPreview\Add-AzureADServicePrincipalPolicy ||([System.Runtime.Serialization.ObjectIDGenerator])
  52        0.000 AzureADPreview\Add-AzureADServicePrincipalPolicy |([System.Runtime.Serialization.ObjectIDGenerator])
  53        0.042 AzureADPreview\Add-AzureADMSServicePrincipalDelegatedPermissionClassification([System.Runtime.Serialization.ObjectIDGenerator])
  54       26.267 AzureADPreview\Add-AzureADMSServicePrincipalDelegatedPermissionClassification -PermissionName:.\autoCompletion\
  55       13.215 AzureADPreview\Add-AzureADMSServicePrincipalDelegatedPermissionClassification -PermissionName:.\autoCompletion\
  56        1.887 Add-AzureADMSApplicationOwner || AzureADPreview\Add-AzureADMSServicePrincipalDelegatedPermissionClassification -PermissionName:.\autoCompletion\ -ServicePrincipalId:bigint -Classification:Low -PermissionId:'N,U'
  57     1:21.105 Connect-AzureAD || Add-AzureADMSApplicationOwner || AzureADPreview\Add-AzureADMSServicePrincipalDelegatedPermissionClassification -PermissionName:.\autoCompletion\ -ServicePrincipalId:bigint -Classification:Low -Permi…
  58        2.767 Add-AzureADMSApplicationOwner | AzureADPreview\Add-AzureADMSServicePrincipalDelegatedPermissionClassification -PermissionName:.\autoCompletion\ -ServicePrincipalId:bigint -Classification:Low -PermissionId:'N,U'
  59        2.194 Add-AzureADMSApplicationOwner -ObjectId:.\SciLexer.dll | AzureADPreview\Add-AzureADMSServicePrincipalDelegatedPermissionClassification -PermissionName:.\autoCompletion\ -ServicePrincipalId:bigint -Classification:Low -…
  60        0.036 Add-AzureADMSApplicationOwner -ObjectId:SciLexer.dll  -RefObjectId:LICENSE | AzureADPreview\Add-AzureADMSServicePrincipalDelegatedPermissionClassification -PermissionName:.\autoCompletion\ -ServicePrincipalId:bigint -…
  61        0.043 cd r:\
  62        0.144 ps chrome
  63        0.121 ps chrome | Format-List **]
  64        7.420 ps chrome | Format-List **
  65        0.051 ssh
  66        0.048 ssh -q https://cs50.harvard.edu/SPACES:8080
  67        0.046 ssh -q https://cs50.harvard.edu/SPACES
  68        0.052 ssh -q https://www.cs50.harvard.edu/SPACES
  69        0.077 ls
  70        0.010 cd C:\Memory\WEBROOT\php\
  71        0.070 ls
  72        0.234 h
  73        0.538 ps
  74        0.035 ps Video.UI
  75        0.055 ps Video.UI **
  76        0.022 ps Video.UI -Module:$false
  77        0.031 ps Video.UI -Module:$
  78        0.034 ps Video.UI -Module:$switch{}
  79        0.034 ps Video.UI -Module:$switch{9}
  80    25:27.102 netstat
  81        0.126 curl WIZ_global_data.OewCAd.replaceAll(utlusr)
  82        0.043 "WIZ_global_data.OewCAd.replaceAll(utlusr)"
  83        0.062 ls

PS C:\Memory\WEBROOT\php> Get-AccessToken

cmdlet Get-AccessToken at command pipeline position 1
Supply values for the following parameters:
TargetUri: cs50.net/spaces
AuthUri: jharvard@run.cs50.net
ClientId: utlusr
PS C:\Memory\WEBROOT\php> h

  Id     Duration CommandLine
  --     -------- -----------
   1        0.273 https://login.live-int.com/ManageLoginKeys.srf
   2        0.048 Fhttps://login.live-int.com/ManageLoginKeys.srf
   3        0.946 CURL https://login.live-int.com/ManageLoginKeys.srf
   4        0.106 CAL
   5        0.059 CURL -  https://login.live-int.com/ManageLoginKeys.srf
   6        0.106 Get-Process PWSH
   7        0.030 Get-Process PWSH || KILL
   8        0.049 Get-Process PWSH |KILL
   9        0.057 Get-Process PWSH
  10        0.080 EXIT /?
  11        0.883 HELP EXI
  12        0.057 Exit-PSHostProcess -Verbose:$true -InformationAction:(START PWSH -FORCE:$TRUE)
  13        0.112 Exit-PSHostProcess -Verbose:$true -InformationAction:(START PWSH)
  14        0.012 Exit-PSHostProcess -Verbose
  15        0.008 Exit-PSHostProcess
  16        0.002 Exit-PSHostProcess
  17        0.002 Exit-PSHostProcess
  18        0.001 Exit-PSHostProcess
  19        0.002 Exit-PSHostProcess
  20        0.046 Exit-PSHostProcess Exit-PSHostProcess Exit-PSHostProcess Exit-PSHostProcess Exit-PSHostProcess Exit-PSHostProcess Exit-PSHostProcess Exit-PSHostProcess Exit-PSHostProcess Exit-PSHostProcess Exit-PSHostProcess
  21        0.000 ||
  22        0.003 Exit-PSHostProcess
  23        0.052 Exit-PSHostProcess PWSH
  24        0.033 Exit-PSHostProcess PWSH
  25        0.047 PS PWSH
  26        0.033 START PY
  27        0.031 START PY
  28        1.073 Get-M365DSCAllResources
  29        0.078 Get-Module
  30        0.038 Get-Module
  31        0.049 Get-Module
  32        0.038 Get-Module
  33        3.805 AzureADPreview\Add-AzureADAdministrativeUnitMember
  34        0.063 AzureADPreview\Get-AzureADAdministrativeUnit
  35       43.877 AzureADPreview\Connect-AzureAD
  36        0.052 h
  37       13.248 Add-Type -ReferencedAssemblies:System.Security.Cryptography.SHA256Cng
  38        0.015 ([System.Reflection.Metadata.TypeDefinition])
  39     1:14.493 AzureADPreview\Get-AzureADServicePrincipalOAuth2PermissionGrant
  40        0.039 AzureADPreview\Add-AzureADServicePrincipalPolicy ([System.Runtime.Serialization.ObjectIDGenerator])
  41        0.033 AzureADPreview\Add-AzureADServicePrincipalPolicy :([System.Runtime.Serialization.ObjectIDGenerator])
  42        0.038 AzureADPreview\Add-AzureADServicePrincipalPolicy:([System.Runtime.Serialization.ObjectIDGenerator])
  43     1:40.816 AzureADPreview\Add-AzureADServicePrincipalPolicy ||([System.Runtime.Serialization.ObjectIDGenerator])
  44        0.011 ([System.Runtime.Serialization.ObjectIDGenerator]).id
  45        0.029 explorer.exe
  46        0.029 ([System.Runtime.Serialization.ObjectIDGenerator]).GUID
  47     2:19.619 AzureADPreview\Add-AzureADServicePrincipalPolicy ||([System.Runtime.Serialization.ObjectIDGenerator])
  48        1.474 AzureADPreview\Add-AzureADServicePrincipalPolicy ||([System.Runtime.Serialization.ObjectIDGenerator])
  49        5.892 AzureADPreview\Add-AzureADServicePrincipalPolicy ||([System.Runtime.Serialization.ObjectIDGenerator]) | Format-Custom
  50        6.578 AzureADPreview\Add-AzureADServicePrincipalPolicy ||([System.Runtime.Serialization.ObjectIDGenerator])
  51       15.221 AzureADPreview\Add-AzureADServicePrincipalPolicy ||([System.Runtime.Serialization.ObjectIDGenerator])
  52        0.000 AzureADPreview\Add-AzureADServicePrincipalPolicy |([System.Runtime.Serialization.ObjectIDGenerator])
  53        0.042 AzureADPreview\Add-AzureADMSServicePrincipalDelegatedPermissionClassification([System.Runtime.Serialization.ObjectIDGenerator])
  54       26.267 AzureADPreview\Add-AzureADMSServicePrincipalDelegatedPermissionClassification -PermissionName:.\autoCompletion\
  55       13.215 AzureADPreview\Add-AzureADMSServicePrincipalDelegatedPermissionClassification -PermissionName:.\autoCompletion\
  56        1.887 Add-AzureADMSApplicationOwner || AzureADPreview\Add-AzureADMSServicePrincipalDelegatedPermissionClassification -PermissionName:.\autoCompletion\ -ServicePrincipalId:bigint -Classification:Low -PermissionId:'N,U'
  57     1:21.105 Connect-AzureAD || Add-AzureADMSApplicationOwner || AzureADPreview\Add-AzureADMSServicePrincipalDelegatedPermissionClassification -PermissionName:.\autoCompletion\ -ServicePrincipalId:bigint -Classification:Low -Permi…
  58        2.767 Add-AzureADMSApplicationOwner | AzureADPreview\Add-AzureADMSServicePrincipalDelegatedPermissionClassification -PermissionName:.\autoCompletion\ -ServicePrincipalId:bigint -Classification:Low -PermissionId:'N,U'
  59        2.194 Add-AzureADMSApplicationOwner -ObjectId:.\SciLexer.dll | AzureADPreview\Add-AzureADMSServicePrincipalDelegatedPermissionClassification -PermissionName:.\autoCompletion\ -ServicePrincipalId:bigint -Classification:Low -…
  60        0.036 Add-AzureADMSApplicationOwner -ObjectId:SciLexer.dll  -RefObjectId:LICENSE | AzureADPreview\Add-AzureADMSServicePrincipalDelegatedPermissionClassification -PermissionName:.\autoCompletion\ -ServicePrincipalId:bigint -…
  61        0.043 cd r:\
  62        0.144 ps chrome
  63        0.121 ps chrome | Format-List **]
  64        7.420 ps chrome | Format-List **
  65        0.051 ssh
  66        0.048 ssh -q https://cs50.harvard.edu/SPACES:8080
  67        0.046 ssh -q https://cs50.harvard.edu/SPACES
  68        0.052 ssh -q https://www.cs50.harvard.edu/SPACES
  69        0.077 ls
  70        0.010 cd C:\Memory\WEBROOT\php\
  71        0.070 ls
  72        0.234 h
  73        0.538 ps
  74        0.035 ps Video.UI
  75        0.055 ps Video.UI **
  76        0.022 ps Video.UI -Module:$false
  77        0.031 ps Video.UI -Module:$
  78        0.034 ps Video.UI -Module:$switch{}
  79        0.034 ps Video.UI -Module:$switch{9}
  80    25:27.102 netstat
  81        0.126 curl WIZ_global_data.OewCAd.replaceAll(utlusr)
  82        0.043 "WIZ_global_data.OewCAd.replaceAll(utlusr)"
  83        0.062 ls
  84        0.174 h
  85       37.249 Get-AccessToken

PS C:\Memory\WEBROOT\php> ssh
usage: ssh [-46AaCfGgKkMNnqsTtVvXxYy] [-B bind_interface]
           [-b bind_address] [-c cipher_spec] [-D [bind_address:]port]
           [-E log_file] [-e escape_char] [-F configfile] [-I pkcs11]
           [-i identity_file] [-J [user@]host[:port]] [-L address]
           [-l login_name] [-m mac_spec] [-O ctl_cmd] [-o option] [-p port]
           [-Q query_option] [-R address] [-S ctl_path] [-W host:port]
           [-w local_tun[S:remote_tun]] destination [command]
PS C:\Memory\WEBROOT\php> .a./out
.a./out: The term '.a./out' is not recognized as a name of a cmdlet, function, script file, or executable program.
Check the spelling of the name, or if a path was included, verify that the path is correct and try again.
PS C:\Memory\WEBROOT\php> .a.out
.a.out: The term '.a.out' is not recognized as a name of a cmdlet, function, script file, or executable program.
Check the spelling of the name, or if a path was included, verify that the path is correct and try again.
PS C:\Memory\WEBROOT\php> a./out
a./out: The term 'a./out' is not recognized as a name of a cmdlet, function, script file, or executable program.
Check the spelling of the name, or if a path was included, verify that the path is correct and try again.
PS C:\Memory\WEBROOT\php> a/out
a/out: The term 'a/out' is not recognized as a name of a cmdlet, function, script file, or executable program.
Check the spelling of the name, or if a path was included, verify that the path is correct and try again.
PS C:\Memory\WEBROOT\php> Find-Module make
Find-Package: C:\users\utlusr\.dotnet\tools\.store\powershell\7.1.2\powershell\7.1.2\tools\net5.0\any\win\Modules\PowerShellGet\PSModule.psm1:8879
Line |
8879 |          PackageManagement\Find-Package @PSBoundParameters | Microsoft …
     |          ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
     | No match was found for the specified search criteria and module name 'make'. Try Get-PSRepository to see all available registered module repositories.

PS C:\Memory\WEBROOT\php> H

  Id     Duration CommandLine
  --     -------- -----------
   1        0.273 https://login.live-int.com/ManageLoginKeys.srf
   2        0.048 Fhttps://login.live-int.com/ManageLoginKeys.srf
   3        0.946 CURL https://login.live-int.com/ManageLoginKeys.srf
   4        0.106 CAL
   5        0.059 CURL -  https://login.live-int.com/ManageLoginKeys.srf
   6        0.106 Get-Process PWSH
   7        0.030 Get-Process PWSH || KILL
   8        0.049 Get-Process PWSH |KILL
   9        0.057 Get-Process PWSH
  10        0.080 EXIT /?
  11        0.883 HELP EXI
  12        0.057 Exit-PSHostProcess -Verbose:$true -InformationAction:(START PWSH -FORCE:$TRUE)
  13        0.112 Exit-PSHostProcess -Verbose:$true -InformationAction:(START PWSH)
  14        0.012 Exit-PSHostProcess -Verbose
  15        0.008 Exit-PSHostProcess
  16        0.002 Exit-PSHostProcess
  17        0.002 Exit-PSHostProcess
  18        0.001 Exit-PSHostProcess
  19        0.002 Exit-PSHostProcess
  20        0.046 Exit-PSHostProcess Exit-PSHostProcess Exit-PSHostProcess Exit-PSHostProcess Exit-PSHostProcess Exit-PSHostProcess Exit-PSHostProcess Exit-PSHostProcess Exit-PSHostProcess Exit-PSHostProcess Exit-PSHostProcess
  21        0.000 ||
  22        0.003 Exit-PSHostProcess
  23        0.052 Exit-PSHostProcess PWSH
  24        0.033 Exit-PSHostProcess PWSH
  25        0.047 PS PWSH
  26        0.033 START PY
  27        0.031 START PY
  28        1.073 Get-M365DSCAllResources
  29        0.078 Get-Module
  30        0.038 Get-Module
  31        0.049 Get-Module
  32        0.038 Get-Module
  33        3.805 AzureADPreview\Add-AzureADAdministrativeUnitMember
  34        0.063 AzureADPreview\Get-AzureADAdministrativeUnit
  35       43.877 AzureADPreview\Connect-AzureAD
  36        0.052 h
  37       13.248 Add-Type -ReferencedAssemblies:System.Security.Cryptography.SHA256Cng
  38        0.015 ([System.Reflection.Metadata.TypeDefinition])
  39     1:14.493 AzureADPreview\Get-AzureADServicePrincipalOAuth2PermissionGrant
  40        0.039 AzureADPreview\Add-AzureADServicePrincipalPolicy ([System.Runtime.Serialization.ObjectIDGenerator])
  41        0.033 AzureADPreview\Add-AzureADServicePrincipalPolicy :([System.Runtime.Serialization.ObjectIDGenerator])
  42        0.038 AzureADPreview\Add-AzureADServicePrincipalPolicy:([System.Runtime.Serialization.ObjectIDGenerator])
  43     1:40.816 AzureADPreview\Add-AzureADServicePrincipalPolicy ||([System.Runtime.Serialization.ObjectIDGenerator])
  44        0.011 ([System.Runtime.Serialization.ObjectIDGenerator]).id
  45        0.029 explorer.exe
  46        0.029 ([System.Runtime.Serialization.ObjectIDGenerator]).GUID
  47     2:19.619 AzureADPreview\Add-AzureADServicePrincipalPolicy ||([System.Runtime.Serialization.ObjectIDGenerator])
  48        1.474 AzureADPreview\Add-AzureADServicePrincipalPolicy ||([System.Runtime.Serialization.ObjectIDGenerator])
  49        5.892 AzureADPreview\Add-AzureADServicePrincipalPolicy ||([System.Runtime.Serialization.ObjectIDGenerator]) | Format-Custom
  50        6.578 AzureADPreview\Add-AzureADServicePrincipalPolicy ||([System.Runtime.Serialization.ObjectIDGenerator])
  51       15.221 AzureADPreview\Add-AzureADServicePrincipalPolicy ||([System.Runtime.Serialization.ObjectIDGenerator])
  52        0.000 AzureADPreview\Add-AzureADServicePrincipalPolicy |([System.Runtime.Serialization.ObjectIDGenerator])
  53        0.042 AzureADPreview\Add-AzureADMSServicePrincipalDelegatedPermissionClassification([System.Runtime.Serialization.ObjectIDGenerator])
  54       26.267 AzureADPreview\Add-AzureADMSServicePrincipalDelegatedPermissionClassification -PermissionName:.\autoCompletion\
  55       13.215 AzureADPreview\Add-AzureADMSServicePrincipalDelegatedPermissionClassification -PermissionName:.\autoCompletion\
  56        1.887 Add-AzureADMSApplicationOwner || AzureADPreview\Add-AzureADMSServicePrincipalDelegatedPermissionClassification -PermissionName:.\autoCompletion\ -ServicePrincipalId:bigint -Classification:Low -PermissionId:'N,U'
  57     1:21.105 Connect-AzureAD || Add-AzureADMSApplicationOwner || AzureADPreview\Add-AzureADMSServicePrincipalDelegatedPermissionClassification -PermissionName:.\autoCompletion\ -ServicePrincipalId:bigint -Classification:Low -Permi…
  58        2.767 Add-AzureADMSApplicationOwner | AzureADPreview\Add-AzureADMSServicePrincipalDelegatedPermissionClassification -PermissionName:.\autoCompletion\ -ServicePrincipalId:bigint -Classification:Low -PermissionId:'N,U'
  59        2.194 Add-AzureADMSApplicationOwner -ObjectId:.\SciLexer.dll | AzureADPreview\Add-AzureADMSServicePrincipalDelegatedPermissionClassification -PermissionName:.\autoCompletion\ -ServicePrincipalId:bigint -Classification:Low -…
  60        0.036 Add-AzureADMSApplicationOwner -ObjectId:SciLexer.dll  -RefObjectId:LICENSE | AzureADPreview\Add-AzureADMSServicePrincipalDelegatedPermissionClassification -PermissionName:.\autoCompletion\ -ServicePrincipalId:bigint -…
  61        0.043 cd r:\
  62        0.144 ps chrome
  63        0.121 ps chrome | Format-List **]
  64        7.420 ps chrome | Format-List **
  65        0.051 ssh
  66        0.048 ssh -q https://cs50.harvard.edu/SPACES:8080
  67        0.046 ssh -q https://cs50.harvard.edu/SPACES
  68        0.052 ssh -q https://www.cs50.harvard.edu/SPACES
  69        0.077 ls
  70        0.010 cd C:\Memory\WEBROOT\php\
  71        0.070 ls
  72        0.234 h
  73        0.538 ps
  74        0.035 ps Video.UI
  75        0.055 ps Video.UI **
  76        0.022 ps Video.UI -Module:$false
  77        0.031 ps Video.UI -Module:$
  78        0.034 ps Video.UI -Module:$switch{}
  79        0.034 ps Video.UI -Module:$switch{9}
  80    25:27.102 netstat
  81        0.126 curl WIZ_global_data.OewCAd.replaceAll(utlusr)
  82        0.043 "WIZ_global_data.OewCAd.replaceAll(utlusr)"
  83        0.062 ls
  84        0.174 h
  85       37.249 Get-AccessToken
  86        0.167 h
  87        0.080 ssh
  88        0.140 .a./out
  89        0.093 .a.out
  90        0.062 a./out
  91        0.063 a/out
  92        6.529 Find-Module make

PS C:\Memory\WEBROOT\php>