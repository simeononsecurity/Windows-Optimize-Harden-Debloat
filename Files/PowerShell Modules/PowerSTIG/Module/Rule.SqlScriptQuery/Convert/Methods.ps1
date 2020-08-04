# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
#region Trace Functions
<#
    .SYNOPSIS
        Returns a query that gets Trace ID's

    .DESCRIPTION
        The SqlScriptResource uses a script resource format with GetScript, TestScript and SetScript.
        The SQL STIG contains queries that will be placed in each of those blocks.
        This function returns the query that will be used in the GetScript block

    .PARAMETER CheckContent
        This is the 'CheckContent' derived from the STIG raw string and holds the query that will be returned
#>
function Get-TraceGetScript
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string[]]
        $CheckContent
    )

    $eventId = Get-EventIdData -CheckContent $CheckContent

    $return = Get-TraceIdQuery -EventId $eventId -GetQuery

    return $return
}

<#
    .SYNOPSIS Get-TraceTestScript
        Returns a query and sub query that gets Trace ID's and Event ID's that should be tracked

    .DESCRIPTION
        The SqlScriptResource uses a script resource format with GetScript, TestScript and SetScript.
        The SQL STIG contains queries that will be placed in each of those blocks.
        This function returns the query that will be used in the TestScript block

    .PARAMETER CheckContent
        This is the 'CheckContent' derived from the STIG raw string and holds the query that will be returned
#>
function Get-TraceTestScript
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string[]]
        $CheckContent
    )

    $eventId = Get-EventIdData -CheckContent $CheckContent

    $return = Get-TraceIdQuery -EventId $eventId

    return $return
}

<#
    .SYNOPSIS
        Returns a SQL Statement that removes a DB

    .DESCRIPTION
        The SqlScriptResource uses a script resource format with GetScript, TestScript and SetScript.
        The SQL STIG contains queries that will be placed in each of those blocks.
        This function returns the query that will be used in the SetScript block

    .PARAMETER FixText
        String that was obtained from the 'Fix' element of the base STIG Rule

    .PARAMETER CheckContent
        Arbitrary in this function but is needed in Get-TraceSetScript
#>
function Get-TraceSetScript
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter()]
        [AllowEmptyString()]
        [string[]]
        $FixText,

        [Parameter()]
        [AllowEmptyString()]
        [string[]]
        $CheckContent
    )

    $eventId = Get-EventIdData -CheckContent $CheckContent

    $sqlScript = "BEGIN IF OBJECT_ID('TempDB.dbo.#StigEvent') IS NOT NULL BEGIN DROP TABLE #StigEvent END IF OBJECT_ID('TempDB.dbo.#Trace') IS NOT NULL BEGIN DROP TABLE #Trace END "
    $sqlScript += "IF OBJECT_ID('TempDB.dbo.#TraceEvent') IS NOT NULL BEGIN DROP TABLE #TraceEvent END CREATE TABLE #StigEvent (EventId INT) INSERT INTO #StigEvent (EventId) VALUES $($eventId) "
    $sqlScript += "CREATE TABLE #Trace (TraceId INT) INSERT INTO #Trace (TraceId) SELECT DISTINCT TraceId FROM sys.fn_trace_getinfo(0)ORDER BY TraceId DESC "
    $sqlScript += "CREATE TABLE #TraceEvent (TraceId INT, EventId INT) DECLARE cursorTrace CURSOR FOR SELECT TraceId FROM #Trace OPEN cursorTrace DECLARE @currentTraceId INT "
    $sqlScript += "FETCH NEXT FROM cursorTrace INTO @currentTraceId WHILE @@FETCH_STATUS = 0 BEGIN INSERT INTO #TraceEvent (TraceId, EventId) SELECT DISTINCT @currentTraceId, EventId "
    $sqlScript += "FROM sys.fn_trace_geteventinfo(@currentTraceId) FETCH NEXT FROM cursorTrace INTO @currentTraceId END CLOSE cursorTrace DEALLOCATE cursorTrace DECLARE @missingStigEventCount INT "
    $sqlScript += "SET @missingStigEventCount = (SELECT COUNT(*) FROM #StigEvent SE LEFT JOIN #TraceEvent TE ON SE.EventId = TE.EventId WHERE TE.EventId IS NULL) IF @missingStigEventCount > 0 "
    $sqlScript += "BEGIN DECLARE @dir nvarchar(4000) DECLARE @tracefile nvarchar(4000) DECLARE @returnCode INT DECLARE @newTraceId INT DECLARE @maxFileSize BIGINT = 5 "
    $sqlScript += "EXEC master.dbo.xp_instance_regread N'HKEY_LOCAL_MACHINE', N'Software\Microsoft\MSSQLServer\Setup', N'SQLPath', @dir OUTPUT, 'no_output' "
    $sqlScript += "SET @tracefile = @dir + N'\Log\PowerStig' EXEC @returnCode = sp_trace_create @traceid = @newTraceId "
    $sqlScript += "OUTPUT, @options = 2, @tracefile = @tracefile, @maxfilesize = @maxFileSize, @stoptime = NULL, @filecount = 2; "
    $sqlScript += "IF @returnCode = 0 BEGIN EXEC sp_trace_setstatus @traceid = @newTraceId, @status = 0 DECLARE cursorMissingStigEvent CURSOR FOR SELECT DISTINCT SE.EventId FROM #StigEvent SE "
    $sqlScript += "LEFT JOIN #TraceEvent TE ON SE.EventId = TE.EventId WHERE TE.EventId IS NULL OPEN cursorMissingStigEvent DECLARE @currentStigEventId INT FETCH NEXT FROM cursorMissingStigEvent "
    $sqlScript += "INTO @currentStigEventId WHILE @@FETCH_STATUS = 0 BEGIN EXEC sp_trace_setevent @traceid = @newTraceId, @eventid = @currentStigEventId, @columnid = NULL, @on = 1 FETCH NEXT "
    $sqlScript += "FROM cursorMissingStigEvent INTO @currentStigEventId END CLOSE cursorMissingStigEvent DEALLOCATE cursorMissingStigEvent EXEC sp_trace_setstatus @traceid = @newTraceId, @status = 1 END END END"

    return $sqlScript
}

<#
    .SYNOPSIS Get-TraceIdQuery
        Returns a query that is used to obtain Trace ID's

    .PARAMETER Query
        An array of queries.
#>
function Get-TraceIdQuery
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $EventId,

        [Parameter()]
        [switch]
        $GetQuery
    )

    $sqlScript = "BEGIN IF OBJECT_ID('TempDB.dbo.#StigEvent') IS NOT NULL BEGIN DROP TABLE #StigEvent END IF OBJECT_ID('TempDB.dbo.#Trace') IS NOT NULL BEGIN DROP TABLE #Trace END "
    $sqlScript += "IF OBJECT_ID('TempDB.dbo.#TraceEvent') IS NOT NULL BEGIN DROP TABLE #TraceEvent END CREATE TABLE #StigEvent (EventId INT) CREATE TABLE #Trace (TraceId INT) "
    $sqlScript += "CREATE TABLE #TraceEvent (TraceId INT, EventId INT) INSERT INTO #StigEvent (EventId) VALUES $($EventId) INSERT INTO #Trace (TraceId) SELECT DISTINCT TraceId "
    $sqlScript += "FROM sys.fn_trace_getinfo(0) DECLARE cursorTrace CURSOR FOR SELECT TraceId FROM #Trace OPEN cursorTrace DECLARE @traceId INT FETCH NEXT FROM cursorTrace INTO @traceId "
    $sqlScript += "WHILE @@FETCH_STATUS = 0 BEGIN INSERT INTO #TraceEvent (TraceId, EventId) SELECT DISTINCT @traceId, EventId FROM sys.fn_trace_geteventinfo(@traceId) FETCH NEXT FROM cursorTrace "
    $sqlScript += "INTO @TraceId END CLOSE cursorTrace DEALLOCATE cursorTrace "

    if ($GetQuery)
    {
        $sqlScript += "SELECT * FROM #StigEvent "
    }

    $sqlScript += "SELECT SE.EventId AS NotFound FROM #StigEvent SE LEFT JOIN #TraceEvent TE ON SE.EventId = TE.EventId "
    $sqlScript += "WHERE TE.EventId IS NULL END"

    return $sqlScript
}

<#
    .SYNOPSIS Get-EventIdQuery
        Returns a query that is used to obtain Event ID's

    .PARAMETER Query
        An array of queries.
#>
function Get-EventIdQuery
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string[]]
        $Query
    )

    foreach ($line in $query)
    {
        if ($line -match "eventid")
        {
            return $line
        }
    }
}

<#
    .SYNOPSIS Get-EventIdData
        Returns the Event ID's that are checked against

    .PARAMETER CheckContent
        This is the 'CheckContent' derived from the STIG raw string and holds the Data that will be returned
#>
function Get-EventIdData
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string[]]
        $CheckContent
    )

    $array = @()

    $eventData = $CheckContent -join " "
    $eventData = ($eventData -split "listed:")[1]
    $eventData = ($eventData -split "\.")[0]

    $eventId = $eventData.Trim()

    $split = $eventId -split ', '

    foreach ($line in $split)
    {
        $add = '(' + $line + ')'

        $array += $add
    }

    $return = $array -join ','

    return $return
}

#endregion Trace Functions

#region Permission Functions
<#
    .SYNOPSIS
        Returns a query that will get a list of users who have access to a certain SQL Permission

    .DESCRIPTION
        The SqlScriptResource uses a script resource format with GetScript, TestScript and SetScript.
        The SQL STIG contains queries that will be placed in each of those blocks.
        This function returns the query that will be used in the GetScript block

    .PARAMETER CheckContent
        This is the 'CheckContent' derived from the STIG raw string and holds the query that will be returned
#>
function Get-PermissionGetScript
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string[]]
        $CheckContent
    )

    $queries = Get-Query -CheckContent $CheckContent

    $return = $queries[0]

    if ($return -notmatch ";$")
    {
        $return = $return + ";"
    }

    return $return
}

<#
    .SYNOPSIS
        Returns a query that will get a list of users who have access to a certain SQL Permission

    .DESCRIPTION
        The SqlScriptResource uses a script resource format with GetScript, TestScript and SetScript.
        The SQL STIG contains queries that will be placed in each of those blocks.
        This function returns the query that will be used in the TestScript block

    .PARAMETER CheckContent
        This is the 'CheckContent' derived from the STIG raw string and holds the query that will be returned
#>
function Get-PermissionTestScript
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string[]]
        $CheckContent
    )

    $queries = Get-Query -CheckContent $CheckContent

    $return = $queries[0]

    if ($return -notmatch ";$")
    {
        $return = $return + ";"
    }

    return $return
}

<#
    .SYNOPSIS Get-PermissionSetScript
        Returns an SQL Statemnt that will remove a user with unauthorized access

    .DESCRIPTION
        The SqlScriptResource uses a script resource format with GetScript, TestScript and SetScript.
        The SQL STIG contains queries that will be placed in each of those blocks.
        This function returns the query that will be used in the SetScript block

    .PARAMETER FixText
        String that was obtained from the 'Fix' element of the base STIG Rule

    .PARAMETER CheckContent
        Arbitrary in this function but is needed in Get-TraceSetScript
#>
function Get-PermissionSetScript
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter()]
        [AllowEmptyString()]
        [string[]]
        $FixText,

        [Parameter()]
        [AllowEmptyString()]
        [string[]]
        $CheckContent
    )

    $permission = ((Get-Query -CheckContent $CheckContent)[0] -split "'")[1] #Get the permission that will be set

    $sqlScript = "DECLARE @name as varchar(512) DECLARE @permission as varchar(512) DECLARE @sqlstring1 as varchar(max) SET @sqlstring1 = 'use master;' SET @permission = '" + $permission + "' "
    $sqlScript += "DECLARE  c1 cursor  for  SELECT who.name AS [Principal Name], what.permission_name AS [Permission Name] FROM sys.server_permissions what INNER JOIN sys.server_principals who "
    $sqlScript += "ON who.principal_id = what.grantee_principal_id WHERE who.name NOT LIKE '##MS%##' AND who.type_desc <> 'SERVER_ROLE' AND who.name <> 'sa'  AND what.permission_name = @permission "
    $sqlScript += "OPEN c1 FETCH next FROM c1 INTO @name,@permission WHILE (@@FETCH_STATUS = 0) BEGIN SET @sqlstring1 = @sqlstring1 + 'REVOKE ' + @permission + ' FROM [' + @name + '];' "
    $sqlScript += "FETCH next FROM c1 INTO @name,@permission END CLOSE c1 DEALLOCATE c1 EXEC ( @sqlstring1 );"

    return $sqlScript
}
#endregion Permission Functions

#region Audit Functions
<#
    .SYNOPSIS Get-AuditGetScript
        Returns a query that will get a list of audit events

    .DESCRIPTION
        The SqlScriptResource uses a script resource format with GetScript, TestScript and SetScript.
        The SQL STIG contains queries that will be placed in each of those blocks.
        This function returns the query that will be used in the GetScript block

    .PARAMETER CheckContent
        This is the 'CheckContent' derived from the STIG raw string and holds the query that will be returned
#>
function Get-AuditGetScript
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string[]]
        $CheckContent
    )

    $collection = Get-AuditEvents -CheckContent $CheckContent

    if ($collection -eq $null)
    {
        $sqlScript = "IF Not Exists (SELECT name AS 'Audit Name', status_desc AS 'Audit Status', audit_file_path AS 'Current Audit File' FROM sys.dm_server_audit_status WHERE status_desc = 'STARTED') Select 'Doest exist'"
    }
    else
    {
        $auditEvents = "('{0}')" -f $(($collection -join "'),('"))

        $sqlScript = 'USE [master] DECLARE @MissingAuditCount INTEGER DECLARE @server_specification_id INTEGER DECLARE @FoundCompliant INTEGER SET @FoundCompliant = 0 '
        $sqlScript += '/* Create a table for the events that we are looking for */ '
        $sqlScript += 'CREATE TABLE #AuditEvents (AuditEvent varchar(100)) INSERT INTO #AuditEvents (AuditEvent) VALUES ' + $auditEvents + ' '
        $sqlScript += '/* Create a cursor to walk through all audits that are enabled at startup */ '
        $sqlScript += 'DECLARE auditspec_cursor CURSOR FOR SELECT s.server_specification_id FROM sys.server_audits a INNER JOIN sys.server_audit_specifications s ON a.audit_guid = s.audit_guid WHERE a.is_state_enabled = 1; '
        $sqlScript += 'OPEN auditspec_cursor FETCH NEXT FROM auditspec_cursor INTO @server_specification_id '
        $sqlScript += 'WHILE @@FETCH_STATUS = 0 AND @FoundCompliant = 0 '
        $sqlScript += '/* Does this specification have the needed events in it? */ '
        $sqlScript += 'BEGIN SET @MissingAuditCount = (SELECT Count(a.AuditEvent) AS MissingAuditCount FROM #AuditEvents a JOIN sys.server_audit_specification_details d ON a.AuditEvent = d.audit_action_name WHERE d.audit_action_name NOT IN (SELECT d2.audit_action_name FROM sys.server_audit_specification_details d2 WHERE d2.server_specification_id = @server_specification_id)) '
        $sqlScript += 'IF @MissingAuditCount = 0 SET @FoundCompliant = 1; '
        $sqlScript += 'FETCH NEXT FROM auditspec_cursor INTO @server_specification_id END CLOSE auditspec_cursor; DEALLOCATE auditspec_cursor; DROP TABLE #AuditEvents '
        $sqlScript += '/* Produce output that works with DSC - records if we do not find the audit events we are looking for */ '
        $sqlScript += 'IF @FoundCompliant > 0 SELECT name FROM sys.sql_logins WHERE principal_id = -1; ELSE SELECT name FROM sys.sql_logins WHERE principal_id = 1'
    }

    return $sqlScript
}

<#
    .SYNOPSIS Get-AuditTestScript
        Returns a query that will get a list of audit events

    .DESCRIPTION
        The SqlScriptResource uses a script resource format with GetScript, TestScript and SetScript.
        The SQL STIG contains queries that will be placed in each of those blocks.
        This function returns the query that will be used in the TestScript block

    .PARAMETER CheckContent
        This is the 'CheckContent' derived from the STIG raw string and holds the query that will be returned
#>
function Get-AuditTestScript
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string[]]
        $CheckContent
    )

    $collection = Get-AuditEvents -CheckContent $CheckContent
    if ($collection -eq $null)
    {
        $sqlScript = "IF Not Exists (SELECT name AS 'Audit Name', status_desc AS 'Audit Status', audit_file_path AS 'Current Audit File' FROM sys.dm_server_audit_status WHERE status_desc = 'STARTED') Select 'Doest exist'"
    }
    else
    {
        $auditEvents = "('{0}')" -f $(($collection -join "'),('"))

        $sqlScript = 'USE [master] DECLARE @MissingAuditCount INTEGER DECLARE @server_specification_id INTEGER DECLARE @FoundCompliant INTEGER SET @FoundCompliant = 0 '
        $sqlScript += '/* Create a table for the events that we are looking for */ '
        $sqlScript += 'CREATE TABLE #AuditEvents (AuditEvent varchar(100)) INSERT INTO #AuditEvents (AuditEvent) VALUES ' + $auditEvents + ' '
        $sqlScript += '/* Create a cursor to walk through all audits that are enabled at startup */ '
        $sqlScript += 'DECLARE auditspec_cursor CURSOR FOR SELECT s.server_specification_id FROM sys.server_audits a INNER JOIN sys.server_audit_specifications s ON a.audit_guid = s.audit_guid WHERE a.is_state_enabled = 1; '
        $sqlScript += 'OPEN auditspec_cursor FETCH NEXT FROM auditspec_cursor INTO @server_specification_id '
        $sqlScript += 'WHILE @@FETCH_STATUS = 0 AND @FoundCompliant = 0 '
        $sqlScript += '/* Does this specification have the needed events in it? */ '
        $sqlScript += 'BEGIN SET @MissingAuditCount = (SELECT Count(a.AuditEvent) AS MissingAuditCount FROM #AuditEvents a JOIN sys.server_audit_specification_details d ON a.AuditEvent = d.audit_action_name WHERE d.audit_action_name NOT IN (SELECT d2.audit_action_name FROM sys.server_audit_specification_details d2 WHERE d2.server_specification_id = @server_specification_id)) '
        $sqlScript += 'IF @MissingAuditCount = 0 SET @FoundCompliant = 1; '
        $sqlScript += 'FETCH NEXT FROM auditspec_cursor INTO @server_specification_id END CLOSE auditspec_cursor; DEALLOCATE auditspec_cursor; DROP TABLE #AuditEvents '
        $sqlScript += '/* Produce output that works with DSC - records if we do not find the audit events we are looking for */ '
        $sqlScript += 'IF @FoundCompliant > 0 SELECT name FROM sys.sql_logins WHERE principal_id = -1; ELSE SELECT name FROM sys.sql_logins WHERE principal_id = 1'
    }
    return $sqlScript
}

<#
    .SYNOPSIS
        Returns an SQL Statemnt that will create an audit

    .DESCRIPTION
        The SqlScriptResource uses a script resource format with GetScript, TestScript and SetScript.
        The SQL STIG contains queries that will be placed in each of those blocks.
        This function returns the query that will be used in the SetScript block

    .PARAMETER FixText
        String that was obtained from the 'Fix' element of the base STIG Rule

    .PARAMETER CheckContent
        Arbitrary in this function but is needed in Get-TraceSetScript
#>
function Get-AuditSetScript
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter()]
        [AllowEmptyString()]
        [string[]]
        $FixText,

        [Parameter()]
        [AllowEmptyString()]
        [string[]]
        $CheckContent
    )

    $sqlScript = '/* See STIG supplemental files for the annotated version of this script */ '
    $sqlScript += 'USE [master] '
    $sqlScript += 'IF EXISTS (SELECT 1 FROM sys.server_audit_specifications WHERE name = ''STIG_AUDIT_SERVER_SPECIFICATION'') ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION WITH (STATE = OFF); '
    $sqlScript += 'IF EXISTS (SELECT 1 FROM sys.server_audit_specifications WHERE name = ''STIG_AUDIT_SERVER_SPECIFICATION'') DROP SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION; '
    $sqlScript += 'IF EXISTS (SELECT 1 FROM sys.server_audits WHERE name = ''STIG_AUDIT'') ALTER SERVER AUDIT STIG_AUDIT WITH (STATE = OFF); '
    $sqlScript += 'IF EXISTS (SELECT 1 FROM sys.server_audits WHERE name = ''STIG_AUDIT'') DROP SERVER AUDIT STIG_AUDIT; '
    $sqlScript += 'CREATE SERVER AUDIT STIG_AUDIT TO FILE (FILEPATH = ''C:\Audits'', MAXSIZE = 200MB, MAX_ROLLOVER_FILES = 50, RESERVE_DISK_SPACE = OFF) WITH (QUEUE_DELAY = 1000, ON_FAILURE = SHUTDOWN) '
    $sqlScript += 'IF EXISTS (SELECT 1 FROM sys.server_audits WHERE name = ''STIG_AUDIT'') ALTER SERVER AUDIT STIG_AUDIT WITH (STATE = ON); '
    $sqlScript += 'CREATE SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION FOR SERVER AUDIT STIG_AUDIT '
    $sqlScript += 'ADD (APPLICATION_ROLE_CHANGE_PASSWORD_GROUP), ADD (AUDIT_CHANGE_GROUP), ADD (BACKUP_RESTORE_GROUP), ADD (DATABASE_CHANGE_GROUP), ADD (DATABASE_OBJECT_CHANGE_GROUP), ADD (DATABASE_OBJECT_OWNERSHIP_CHANGE_GROUP), ADD (DATABASE_OBJECT_PERMISSION_CHANGE_GROUP), '
    $sqlScript += 'ADD (DATABASE_OPERATION_GROUP), ADD (DATABASE_OWNERSHIP_CHANGE_GROUP), ADD (DATABASE_PERMISSION_CHANGE_GROUP), ADD (DATABASE_PRINCIPAL_CHANGE_GROUP), ADD (DATABASE_PRINCIPAL_IMPERSONATION_GROUP), ADD (DATABASE_ROLE_MEMBER_CHANGE_GROUP), '
    $sqlScript += 'ADD (DBCC_GROUP), ADD (FAILED_LOGIN_GROUP), ADD (LOGIN_CHANGE_PASSWORD_GROUP), ADD (LOGOUT_GROUP), ADD (SCHEMA_OBJECT_CHANGE_GROUP), ADD (SCHEMA_OBJECT_OWNERSHIP_CHANGE_GROUP), ADD (SCHEMA_OBJECT_PERMISSION_CHANGE_GROUP), '
    $sqlScript += 'ADD (SERVER_OBJECT_CHANGE_GROUP), ADD (SERVER_OBJECT_OWNERSHIP_CHANGE_GROUP), ADD (SERVER_OBJECT_PERMISSION_CHANGE_GROUP), ADD (SERVER_OPERATION_GROUP), ADD (SERVER_PERMISSION_CHANGE_GROUP), ADD (SERVER_PRINCIPAL_CHANGE_GROUP), ADD (SERVER_PRINCIPAL_IMPERSONATION_GROUP), '
    $sqlScript += 'ADD (SERVER_ROLE_MEMBER_CHANGE_GROUP), ADD (SERVER_STATE_CHANGE_GROUP), ADD (SUCCESSFUL_LOGIN_GROUP), ADD (TRACE_CHANGE_GROUP) WITH (STATE = ON)'

    return $sqlScript
}

<#
    .SYNOPSIS
        Returns a string of the audit events found in CheckContent

    .DESCRIPTION
        This function returns the audit events found in CheckContent as a comma-delimited string, suitable for insertion into a SQL statement.

    .PARAMETER FixText
        String that was obtained from the 'CheckContent' element of the base STIG Rule

    .PARAMETER CheckContent
        The STIG content that contains possible audit events
#>
function Get-AuditEvents
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string[]]
        $CheckContent
    )

    $collection = @()
    $pattern = '([A-Z_]+)_GROUP(?!\x27|\x22)'
    foreach ($line in $CheckContent)
    {
        $auditEvents = $line | Select-String -Pattern $pattern -AllMatches
        foreach ($auditEvent in $auditEvents.Matches)
        {
            $collection += $auditEvent
        }
    }
    # Return an array of found SQL audit events
    return $collection
}
#endregion Audit Functions

#region PlainSQL Functions
<#
    .SYNOPSIS
        Returns a plain SQL query from $CheckContent

    .DESCRIPTION
        The SqlScriptResource uses a script resource format with GetScript, TestScript and SetScript.
        The SQL STIG contains queries that will be placed in each of those blocks.
        This function returns the query that will be used in the GetScript block

    .PARAMETER CheckContent
        This is the 'CheckContent' derived from the STIG raw string and holds the query that will be returned
#>
function Get-PlainSQLGetScript
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string[]]
        $CheckContent
    )

    $return = Get-SQLQuery -CheckContent $CheckContent

    return $return
}

<#
    .SYNOPSIS
        Returns a T-SQL query

    .DESCRIPTION
        The SqlScriptResource uses a script resource format with GetScript, TestScript and SetScript.
        The SQL STIG contains queries that will be placed in each of those blocks.
        This function returns the query that will be used in the TestScript block

    .PARAMETER CheckContent
        This is the 'CheckContent' derived from the STIG raw string and holds the query that will be returned
#>
function Get-PlainSQLTestScript
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string[]]
        $CheckContent
    )

    $return = Get-SQLQuery -CheckContent $CheckContent

    return $return
}

<#
    .SYNOPSIS
        Returns a T-SQL query

    .DESCRIPTION
        The SqlScriptResource uses a script resource format with GetScript, TestScript and SetScript.
        The SQL STIG contains queries that will be placed in each of those blocks.
        This function returns the query that will be used in the SetScript block

    .PARAMETER FixText
        String that was obtained from the 'Fix' element of the base STIG Rule

    .PARAMETER CheckContent
        Arbitrary in this function but is needed in Get-TraceSetScript
#>
function Get-PlainSQLSetScript
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter()]
        [AllowEmptyString()]
        [string[]]
        $FixText,

        [Parameter()]
        [AllowEmptyString()]
        [string[]]
        $CheckContent
    )

    $return = Get-SQLQuery -CheckContent $FixText

    return $return
}
#endregion PlainSQL Functions

#region SysAdminAccount Functions
<#
    .SYNOPSIS
        Returns a T-SQL query from $CheckContent

    .DESCRIPTION
        The SqlScriptResource uses a script resource format with GetScript, TestScript and SetScript.
        The SQL STIG contains queries that will be placed in each of those blocks.
        This function returns the query that will be used in the GetScript block

    .PARAMETER CheckContent
        This is the 'CheckContent' derived from the STIG raw string and holds the query that will be returned
#>
function Get-SysAdminAccountGetScript
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string[]]
        $CheckContent
    )

    $return = "USE [master] SELECT name, is_disabled FROM sys.sql_logins WHERE principal_id = 1 AND is_disabled <> 1;"

    return $return
}

<#
    .SYNOPSIS
        Returns a T-SQL query

    .DESCRIPTION
        The SqlScriptResource uses a script resource format with GetScript, TestScript and SetScript.
        The SQL STIG contains queries that will be placed in each of those blocks.
        This function returns the query that will be used in the TestScript block

    .PARAMETER CheckContent
        This is the 'CheckContent' derived from the STIG raw string and holds the query that will be returned
#>
function Get-SysAdminAccountTestScript
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string[]]
        $CheckContent
    )

    $return = "USE [master] SELECT name, is_disabled FROM sys.sql_logins WHERE principal_id = 1 AND is_disabled <> 1;"

    return $return
}

<#
    .SYNOPSIS
        Returns a T-SQL query

    .DESCRIPTION
        The SqlScriptResource uses a script resource format with GetScript, TestScript and SetScript.
        The SQL STIG contains queries that will be placed in each of those blocks.
        This function returns the query that will be used in the SetScript block

    .PARAMETER FixText
        String that was obtained from the 'Fix' element of the base STIG Rule

    .PARAMETER CheckContent
        Arbitrary in this function but is needed in Get-TraceSetScript
#>
function Get-SysAdminAccountSetScript
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter()]
        [AllowEmptyString()]
        [string[]]
        $FixText,

        [Parameter()]
        [AllowEmptyString()]
        [string[]]
        $CheckContent
    )

    $return =  "USE [master] DECLARE @SysAdminAccountName varchar(50), @cmd NVARCHAR(100), @saDisabled int "
    $return += "SET @SysAdminAccountName = (SELECT name FROM sys.sql_logins WHERE principal_id = 1) "
    $return += "SELECT @cmd = N'ALTER LOGIN ['+@SysAdminAccountName+'] DISABLE;' "
    $return += "SET @saDisabled = (SELECT is_disabled FROM sys.sql_logins WHERE principal_id = 1) "
    $return += "IF @saDisabled <> 1 exec sp_executeSQL @cmd;"

    return $return
}
#endregion SysAdminAccount Functions

#region SaAccountRename Functions
<#
    .SYNOPSIS
        Returns a T-SQL query

    .DESCRIPTION
        The SqlScriptResource uses a script resource format with GetScript, TestScript and SetScript.
        The SQL STIG contains queries that will be placed in each of those blocks.
        This function returns the query that will be used in the SetScript block

    .PARAMETER FixText
        String that was obtained from the 'Fix' element of the base STIG Rule

    .PARAMETER CheckContent
        Arbitrary in this function but is needed in Get-TraceSetScript
#>
function Get-SaAccountRenameGetScript
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter()]
        [AllowEmptyString()]
        [string[]]
        $FixText,

        [Parameter()]
        [AllowEmptyString()]
        [string[]]
        $CheckContent
    )

    $return = "SELECT name FROM sys.server_principals WHERE TYPE = 'S' and name not like '%##%'"

    return $return
}

<#
    .SYNOPSIS
        Returns a T-SQL query

    .DESCRIPTION
        The SqlScriptResource uses a script resource format with GetScript, TestScript and SetScript.
        The SQL STIG contains queries that will be placed in each of those blocks.
        This function returns the query that will be used in the SetScript block

    .PARAMETER FixText
        String that was obtained from the 'Fix' element of the base STIG Rule

    .PARAMETER CheckContent
        Arbitrary in this function but is needed in Get-TraceSetScript
#>
function Get-SaAccountRenameTestScript
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter()]
        [AllowEmptyString()]
        [string[]]
        $FixText,

        [Parameter()]
        [AllowEmptyString()]
        [string[]]
        $CheckContent
    )

    $return = "SELECT name FROM sys.server_principals WHERE TYPE = 'S' and name = 'sa'"

    return $return
}

<#
    .SYNOPSIS
        Returns a T-SQL query

    .DESCRIPTION
        The SqlScriptResource uses a script resource format with GetScript, TestScript and SetScript.
        The SQL STIG contains queries that will be placed in each of those blocks.
        This function returns the query that will be used in the SetScript block

    .PARAMETER FixText
        String that was obtained from the 'Fix' element of the base STIG Rule

    .PARAMETER CheckContent
        Arbitrary in this function but is needed in Get-TraceSetScript
#>
function Get-SaAccountRenameSetScript
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter()]
        [AllowEmptyString()]
        [string[]]
        $FixText,

        [Parameter()]
        [AllowEmptyString()]
        [string[]]
        $CheckContent
    )

    $return = 'alter login sa with name = [$(saAccountName)]'

    return $return
}

<#
    .SYNOPSIS
        Return the string used to translate varaibles into the SqlQueryScript
#>
function Get-SaAccountRenameVariable
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    ()

    $return = "saAccountName={0}"

    return $return
}

#endregion SaAccountRename Functions

#region trace file limits
<#
    .SYNOPSIS
        Returns a plain SQL query

    .DESCRIPTION
        The SqlScriptResource uses a script resource format with GetScript, TestScript and SetScript.
        The SQL STIG contains queries that will be placed in each of those blocks.
        This function returns the query that will be used in the SetScript block

    .PARAMETER FixText
        String that was obtained from the 'Fix' element of the base STIG Rule

    .PARAMETER CheckContent
        Arbitrary in this function but is needed in Get-TraceSetScript
#>
function Get-TraceFileLimitGetScript
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter()]
        [AllowEmptyString()]
        [string[]]
        $FixText,

        [Parameter()]
        [AllowEmptyString()]
        [string[]]
        $CheckContent
    )

    $getScript = "SELECT * FROM ::fn_trace_getinfo(NULL)"

    return $getScript
}

<#
    .SYNOPSIS
        Returns a plain SQL query

    .DESCRIPTION
        The SqlScriptResource uses a script resource format with GetScript, TestScript and SetScript.
        The SQL STIG contains queries that will be placed in each of those blocks.
        This function returns the query that will be used in the SetScript block

    .PARAMETER FixText
        String that was obtained from the 'Fix' element of the base STIG Rule

    .PARAMETER CheckContent
        Arbitrary in this function but is needed in Get-TraceSetScript
#>
function Get-TraceFileLimitTestScript
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter()]
        [AllowEmptyString()]
        [string[]]
        $FixText,

        [Parameter()]
        [AllowEmptyString()]
        [string[]]
        $CheckContent
    )

    $testScript = "DECLARE @traceFilePath nvarchar(500) "
    $testScript += "DECLARE @desiredFileSize bigint "
    $testScript += "DECLARE @desiredMaxFiles int "
    $testScript += "DECLARE @currentFileSize bigint "
    $testScript += "DECLARE @currentMaxFiles int "
    $testScript += "SET @traceFilePath = N'`$(TraceFilePath)' "
    $testScript += "SET @currentFileSize = (SELECT max_size from sys.traces where path LIKE (@traceFilePath + '%')) "
    $testScript += "SET @currentMaxFiles = (SELECT max_files from sys.traces where path LIKE (@traceFilePath + '%')) "
    $testScript += "IF (@currentFileSize != `$(MaxTraceFileSize)) "
    $testScript += "BEGIN "
    $testScript += "PRINT 'file size not in desired state' "
    $testScript += "SELECT max_size from sys.traces where path LIKE (@traceFilePath + '%') "
    $testScript += "END "
    $testScript += "IF (@currentMaxFiles != `$(MaxRollOverFileCount)) "
    $testScript += "BEGIN "
    $testScript += "PRINT 'max files not in desired state'"
    $testScript += "SELECT max_files from sys.traces where path LIKE (@traceFilePath + '%') "
    $testScript += "END"

    return $testScript
}

<#
    .SYNOPSIS
        Returns a plain SQL query

    .DESCRIPTION
        The SqlScriptResource uses a script resource format with GetScript, TestScript and SetScript.
        The SQL STIG contains queries that will be placed in each of those blocks.
        This function returns the query that will be used in the SetScript block

    .PARAMETER FixText
        String that was obtained from the 'Fix' element of the base STIG Rule

    .PARAMETER CheckContent
        Arbitrary in this function but is needed in Get-TraceSetScript
#>
function Get-TraceFileLimitSetScript
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter()]
        [AllowEmptyString()]
        [string[]]
        $FixText,

        [Parameter()]
        [AllowEmptyString()]
        [string[]]
        $CheckContent
    )

    $setScript = "DECLARE @new_trace_id INT; "
    $setScript += "DECLARE @maxsize bigint "
    $setScript += "DECLARE @maxRolloverFiles int "
    $setScript += "DECLARE @traceId int "
    $setScript += "DECLARE @traceFilePath nvarchar(500) "

    $setScript += "SET @traceFilePath = N'`$(TraceFilePath)' "
    $setScript += "SET @traceId = (Select Id from sys.traces where path LIKE (@traceFilePath + '%')) "
    $setScript += "SET @maxsize = `$(MaxTraceFileSize) "
    $setScript += "SET @maxRolloverFiles = `$(MaxRollOverFileCount) "

    $setScript += "EXEC sp_trace_setstatus @traceid, @status = 2 "

    $setScript += "EXECUTE master.dbo.sp_trace_create "
    $setScript += "    @new_trace_id OUTPUT, "
    $setScript += "    6, "
    $setScript += "    @traceFilePath, "
    $setScript += "    @maxsize, "
    $setScript += "    NULL, "
    $setScript += "    @maxRolloverFiles "
    #$setScript += "    GO"

    return $setScript
}

<#
    .SYNOPSIS
        Return the string used to translate varaibles into the SqlQueryScript
#>
function Get-TraceFileLimitVariable
{
    [CmdletBinding()]
    [OutputType([string[]])]
    param
    ()

    $variable = @('TraceFilePath={0}','MaxRollOverFileCount={1}','MaxTraceFileSize={2}')

    return $variable
}

#endregion trace file limits

#region shutdown on error
<#
    .SYNOPSIS
        Returns a plain SQL query

    .DESCRIPTION
        The SqlScriptResource uses a script resource format with GetScript, TestScript and SetScript.
        The SQL STIG contains queries that will be placed in each of those blocks.
        This function returns the query that will be used in the SetScript block

    .PARAMETER FixText
        String that was obtained from the 'Fix' element of the base STIG Rule

    .PARAMETER CheckContent
        Arbitrary in this function but is needed in Get-TraceSetScript
#>
function Get-ShutdownOnErrorGetScript
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter()]
        [AllowEmptyString()]
        [string[]]
        $FixText,

        [Parameter()]
        [AllowEmptyString()]
        [string[]]
        $CheckContent
    )

    $getScript = "SELECT * FROM ::fn_trace_getinfo(NULL)"

    return $getScript
}

<#
    .SYNOPSIS
        Returns a plain SQL query

    .DESCRIPTION
        The SqlScriptResource uses a script resource format with GetScript, TestScript and SetScript.
        The SQL STIG contains queries that will be placed in each of those blocks.
        This function returns the query that will be used in the SetScript block

    .PARAMETER FixText
        String that was obtained from the 'Fix' element of the base STIG Rule

    .PARAMETER CheckContent
        Arbitrary in this function but is needed in Get-TraceSetScript
#>
function Get-ShutdownOnErrorTestScript
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter()]
        [AllowEmptyString()]
        [string[]]
        $FixText,

        [Parameter()]
        [AllowEmptyString()]
        [string[]]
        $CheckContent
    )

    $setScript =  "DECLARE @traceId int "
    $setScript += "SET @traceId = (SELECT traceId FROM ::fn_trace_getinfo(NULL) WHERE Value = 6) "
    $setScript += "IF (@traceId IS NULL) "
    $setScript += "SELECT traceId FROM ::fn_trace_getinfo(NULL) "
    $setScript += "ELSE "
    $setScript += "Print NULL"

    return $setScript
}

<#
    .SYNOPSIS
        Returns a plain SQL query

    .DESCRIPTION
        The SqlScriptResource uses a script resource format with GetScript, TestScript and SetScript.
        The SQL STIG contains queries that will be placed in each of those blocks.
        This function returns the query that will be used in the SetScript block

    .PARAMETER FixText
        String that was obtained from the 'Fix' element of the base STIG Rule

    .PARAMETER CheckContent
        Arbitrary in this function but is needed in Get-TraceSetScript
#>
function Get-ShutdownOnErrorSetScript
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter()]
        [AllowEmptyString()]
        [string[]]
        $FixText,

        [Parameter()]
        [AllowEmptyString()]
        [string[]]
        $CheckContent
    )

    $setScript += "DECLARE @new_trace_id INT; "
    $setScript += "DECLARE @traceid INT; "
    $setScript += "SET @traceId  = (SELECT traceId FROM ::fn_trace_getinfo(NULL) WHERE Value = 6) "
    $setScript += "EXECUTE master.dbo.sp_trace_create "
    $setScript += "    @results = @new_trace_id OUTPUT, "
    $setScript += "    @options = 6, "
    $setScript += "    @traceFilePath = N'`$(TraceFilePath)'"

    return $setScript
}

<#
    .SYNOPSIS
        Return the string used to translate varaibles into the SqlQueryScript
#>
function Get-ShutdownOnErrorVariable
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    ()

    $variable = 'TraceFilePath={0}'

    return $variable
}
#endregion shutdown on error

#region view any database
<#
    .SYNOPSIS
        Returns a plain SQL query

    .DESCRIPTION
        The SqlScriptResource uses a script resource format with GetScript, TestScript and SetScript.
        The SQL STIG contains queries that will be placed in each of those blocks.
        This function returns the query that will be used in the SetScript block

    .PARAMETER FixText
        String that was obtained from the 'Fix' element of the base STIG Rule

    .PARAMETER CheckContent
        Arbitrary in this function but is needed in Get-TraceSetScript
#>
function Get-ViewAnyDatabaseGetScript
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter()]
        [AllowEmptyString()]
        [string[]]
        $FixText,

        [Parameter()]
        [AllowEmptyString()]
        [string[]]
        $CheckContent
    )

    $getScript = "SELECT who.name AS [Principal Name], "
    $getScript += "who.type_desc AS [Principal Type], "
    $getScript += "who.is_disabled AS [Principal Is Disabled], "
    $getScript += "what.state_desc AS [Permission State], "
    $getScript += "what.permission_name AS [Permission Name] "
    $getScript += "FROM sys.server_permissions what "
    $getScript += "INNER JOIN sys.server_principals who "
    $getScript += "ON who.principal_id = what.grantee_principal_id "
    $getScript += "WHERE what.permission_name = 'View any database' "
    $getScript += "AND who.type_desc = 'SERVER_ROLE' ORDER BY who.name"

    return $getScript
}

<#
    .SYNOPSIS
        Returns a plain SQL query

    .DESCRIPTION
        The SqlScriptResource uses a script resource format with GetScript, TestScript and SetScript.
        The SQL STIG contains queries that will be placed in each of those blocks.
        This function returns the query that will be used in the SetScript block

    .PARAMETER FixText
        String that was obtained from the 'Fix' element of the base STIG Rule

    .PARAMETER CheckContent
        Arbitrary in this function but is needed in Get-TraceSetScript
#>
function Get-ViewAnyDatabaseTestScript
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter()]
        [AllowEmptyString()]
        [string[]]
        $FixText,

        [Parameter()]
        [AllowEmptyString()]
        [string[]]
        $CheckContent
    )

    $testScript = "SELECT who.name AS [Principal Name], "
    $testScript += "who.type_desc AS [Principal Type], "
    $testScript += "who.is_disabled AS [Principal Is Disabled], "
    $testScript += "what.state_desc AS [Permission State], "
    $testScript += "what.permission_name AS [Permission Name] "
    $testScript += "FROM "
    $testScript += "sys.server_permissions what "
    $testScript += "INNER JOIN sys.server_principals who "
    $testScript += "ON who.principal_id = what.grantee_principal_id "
    $testScript += "WHERE what.permission_name = 'View any database' "
    $testScript += "AND who.type_desc = 'SERVER_ROLE' "
    $testScript += "AND who.name != '`$(ViewAnyDbUser)' "
    $testScript += "ORDER BY who.name"

    return $testScript
}

<#
    .SYNOPSIS
        Returns a plain SQL query

    .DESCRIPTION
        The SqlScriptResource uses a script resource format with GetScript, TestScript and SetScript.
        The SQL STIG contains queries that will be placed in each of those blocks.
        This function returns the query that will be used in the SetScript block

    .PARAMETER FixText
        String that was obtained from the 'Fix' element of the base STIG Rule

    .PARAMETER CheckContent
        Arbitrary in this function but is needed in Get-TraceSetScript
#>
function Get-ViewAnyDatabaseSetScript
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter()]
        [AllowEmptyString()]
        [string[]]
        $FixText,

        [Parameter()]
        [AllowEmptyString()]
        [string[]]
        $CheckContent
    )

    $setScript = "REVOKE External access assembly TO '`$(ViewAnyDbUser)'"

    return $setScript

}


<#
    .SYNOPSIS
        Return the string used to translate varaibles into the SqlQueryScript
#>
function Get-ViewAnyDatabaseVariable
{
    [CmdletBinding()]
    [OutputType([string[]])]
    param
    ()

    $variable = @('ViewAnyDbUser={0}')

    return $variable
}
#endregion view any database

#region change database owner
<#
    .SYNOPSIS
        Returns a plain SQL query

    .DESCRIPTION
        The SqlScriptResource uses a script resource format with GetScript, TestScript and SetScript.
        The SQL STIG contains queries that will be placed in each of those blocks.
        This function returns the query that will be used in the SetScript block

    .PARAMETER FixText
        String that was obtained from the 'Fix' element of the base STIG Rule

    .PARAMETER CheckContent
        Arbitrary in this function but is needed in Get-TraceSetScript
#>
function Get-ChangeDatabaseOwnerGetScript
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter()]
        [AllowEmptyString()]
        [string[]]
        $FixText,

        [Parameter()]
        [AllowEmptyString()]
        [string[]]
        $CheckContent
    )

    $getscript = "select suser_sname(owner_sid) AS 'Owner' from sys.databases where name = `$(Database)"

    return $getScript
}

<#
    .SYNOPSIS
        Returns a plain SQL query

    .DESCRIPTION
        The SqlScriptResource uses a script resource format with GetScript, TestScript and SetScript.
        The SQL STIG contains queries that will be placed in each of those blocks.
        This function returns the query that will be used in the SetScript block

    .PARAMETER FixText
        String that was obtained from the 'Fix' element of the base STIG Rule

    .PARAMETER CheckContent
        Arbitrary in this function but is needed in Get-TraceSetScript
#>
function Get-ChangeDatabaseOwnerTestScript
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter()]
        [AllowEmptyString()]
        [string[]]
        $FixText,

        [Parameter()]
        [AllowEmptyString()]
        [string[]]
        $CheckContent
    )

    $testScript = "SELECT suser_sname(owner_sid) AS 'Owner' FROM sys.databases WHERE name = N'`$(Database)' and suser_sname(owner_sid) != N'`$(DatabaseOwner)';"

    return $testScript
}

<#
    .SYNOPSIS
        Returns a plain SQL query

    .DESCRIPTION
        The SqlScriptResource uses a script resource format with GetScript, TestScript and SetScript.
        The SQL STIG contains queries that will be placed in each of those blocks.
        This function returns the query that will be used in the SetScript block

    .PARAMETER FixText
        String that was obtained from the 'Fix' element of the base STIG Rule

    .PARAMETER CheckContent
        Arbitrary in this function but is needed in Get-TraceSetScript
#>
function Get-ChangeDatabaseOwnerSetScript
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter()]
        [AllowEmptyString()]
        [string[]]
        $FixText,

        [Parameter()]
        [AllowEmptyString()]
        [string[]]
        $CheckContent
    )

    $setScript = "ALTER AUTHORIZATION ON DATABASE::`$(Database) to `$(DatabaseOwner)"

    return $setScript
}

<#
    .SYNOPSIS
        Return the string used to translate varaibles into the SqlQueryScript
#>
function Get-ChangeDatabaseOwnerVariable
{
    [CmdletBinding()]
    [OutputType([string[]])]
    param
    ()

    $variable = @('DatabaseOwner={0}')

    return $variable
}
#endregion change database owner

#region Helper Functions
<#
    .SYNOPSIS
        Returns all queries found withing the 'CheckContent'

    .DESCRIPTION
        This function parses the 'CheckContent' to find all queies and extract them
        Not all queries may be used by later functions and will be separated then.
        Some functions require variations of the queries returned thus the reason for
        returning all queries found.

        Note that this function worked well for SQL Server 2012 STIGs. An upgraded version of this function is
        available for more robust SQL handling: Get-SQLQuery.

    .PARAMETER CheckContent
        This is the 'CheckContent' derived from the STIG raw string and holds the query that will be returned
#>
function Get-Query
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string[]]
        $CheckContent
    )

    $collection = @()
    $queries = @()

    if ($CheckContent.Count -gt 1)
    {
        $CheckContent = $CheckContent -join ' '
    }

    $lines = $CheckContent -split "(?=USE|SELECT)"

    foreach ($line in $lines)
    {
        if ($line -match "^(Select|SELECT)")
        {
            $collection += $line
        }
        <#if ($line -match "^(Use|USE)")
        {
            $collection += $line
        }#>
    }

    foreach ($line in $collection)
    {
        if ($line -notmatch ";")
        {
            $query = ($line -split "(\s+GO)")[0]
        }
        else
        {
            $query = ($line -split "(?<=;)")[0]
        }

        $queries += $query
    }

    return $queries
}

<#
    .SYNOPSIS
        Returns all Queries found withing the 'CheckContent'
        This is an updated version of an older, simpler function called Get-Query, written for SQL Server 2012 STIGs.

    .DESCRIPTION
        This function parses the 'CheckContent' to find all queies and extract them
        Not all queries may be used by later functions and will be separated then.
        Some functions require variations of the queries returned thus the reason for
        returning all queries found.

        This function is able to parse a large variety of common SQL queries including action queries and those with
        parenthetical clauses such as IN clauses.

    .PARAMETER CheckContent
        This is the 'CheckContent' derived from the STIG raw string and holds the query that will be returned
#>
function Get-SQLQuery
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string[]]
        $CheckContent
    )

    $collection = @()
    $queries = @()
    [boolean] $scriptInitiated = $false
    [boolean] $scriptTerminated = $false
    [boolean] $inScriptClause = $false
    [int] $parenthesesLeftCount = 0
    [int] $parenthesesRightCount = 0
    [int] $iParenthesesOffset = 0

    foreach ($line in $CheckContent)
    {
        # Clean the line first
        $line = $line.Trim()

        # Search for a SQL initiator if we haven't found one
        if ($line -match "^(select\s|use\s|alter\s|drop\s)")
        {
            $scriptInitiated = $true
            $collection += $line

            # Get the parentheses offset by accumulating match counters
            $leftParenResults = $line | Select-String '\(' -AllMatches
            $parenthesesLeftCount += $leftParenResults.Matches.Count
            $rightParenResults = $line | Select-String '\)' -AllMatches
            $parenthesesRightCount += $rightParenResults.Matches.Count
            $iParenthesesOffset = $parenthesesLeftCount - $parenthesesRightCount
        }
        # If a SQL script is started, let's see what we have to add to it, if anything
        elseif ($scriptInitiated)
        {
            # Get the parentheses offset by accumulating match counters
            $leftParenResults = $line | Select-String '\(' -AllMatches
            $parenthesesLeftCount += $leftParenResults.Matches.Count
            $rightParenResults = $line | Select-String '\)' -AllMatches
            $parenthesesRightCount += $rightParenResults.Matches.Count
            $iParenthesesOffset = $parenthesesLeftCount - $parenthesesRightCount

            # Look for SQL statement fragments
            if ($line -match "(from\s|\sas\s|join\s|where\s|^and\s|order\s|\s(in|IN)(\s\(|\())")
            {
                $collection += $line

                if ($line -match "\sin(\s\(|\()")
                {
                    # Start of a group IN clause
                    $inScriptClause = $true
                }
            }
            # If we are inside of a group IN clause, we need to collect statements until the IN clause terminates
            elseif ($inScriptClause)
            {
                $collection += $line
                if ($line -match "\)")
                {
                    # If the parenthesis we just found closes all that have been opened, the group clause can be closed
                    if ($iParenthesesOffset % 2 -eq 0)
                    {
                        $inScriptClause = $false
                    }
                }
            }
            # If we are not in a clause, let's look for a termination for the script
            if ($inScriptClause -eq $false)
            {
                if ($line -notmatch "(select\s|use\s|alter\s|from\s|\sas\s|join\s|where\s|^and\s|order\s|\s(in|IN)(\s\(|\()|go|;|\))")
                {
                    $scriptTerminated = $true
                }
            }
        }
        # If we found one (or more) criteria for terminating the SQL script, then build the query and add it to the queries collection
        if ($scriptTerminated)
        {
            $query = $collection -join " "
            $queries += $query
            $collection = @()
            $scriptInitiated = $false
            $scriptTerminated = $false
        }
    }

    # Was a script parsed but we reached the end of CheckContent before we closed it out?
    if ($scriptInitiated -and $scriptTerminated -eq $false)
    {
        $query = $collection -join " "
        $queries += $query
    }

    return $queries
}

<#
    .SYNOPSIS
        Labels a rule as a specific type to retrieve the proper T-Sql script used to enforce the STIG rule.

    .DESCRIPTION
        The SQL STIG is enforced with T-SQL scripts.  This functions labels a rule as a specific type
        so the proper T-SQL scripts can dynamically be retrieved.

    .PARAMETER CheckContent
        This is the 'CheckContent' derived from the STIG raw string and holds the query that will be returned
#>
function Get-SqlRuleType
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [string[]]
        $CheckContent
    )

    $content = $CheckContent -join " "

    switch ($content)
    {
        # Standard trace and event ID parsers
        {
            $PSItem -Match 'SELECT' -and
            $PSItem -Match 'traceid' -and
            $PSItem -Match 'eventid' -and
            $PSItem -NotMatch 'SHUTDOWN_ON_ERROR'
        }
        {
            $ruleType = 'Trace'
        }
        # Standard permissions parsers
        {
            $PSItem -Match 'SELECT' -and
            $PSItem -Match 'direct access.*server-level'
        }
        {
            $ruleType = 'Permission'
        }
        # Audit rules for SQL Server 2014 and beyond
        {
            $PSItem -Match "TRACE_CHANGE_GROUP" -or #V-79239,79291,79293,29295
            $PSItem -Match "DATABASE_OBJECT_OWNERSHIP_CHANGE_GROUP" -or #V-79259,79261,79263,79265,79275,79277
            $PSItem -Match "SCHEMA_OBJECT_CHANGE_GROUP" -or #V-79267,79269,79279,79281
            $PSItem -Match "SUCCESSFUL_LOGIN_GROUP" -or #V-79287,79297
            $PSItem -Match "FAILED_LOGIN_GROUP" -or #V-79289
            $PSItem -Match "status_desc = 'STARTED'" #V-79141
        }
        {
            $ruleType = 'Audit'
        }
        # sa account rename
        {
            $PSItem -Match "'sa' account name has been changed"
        }
        {
            $ruleType = 'SaAccountRename'
        }
        # sa account rules
        {
            $PSItem -Match '(\s|\[)principal_id(\s*|\]\s*)\=\s*1'
        }
        {
            $ruleType = 'SysAdminAccount'
        }
        # trace file limits
        {
            $PSItem -Match 'SQL Server audit setting on the maximum number of files of the trace'
        }
        {
            $ruleType = 'TraceFileLimit'
        }
        # shutdown on error
        {
            $PSItem -match 'SHUTDOWN_ON_ERROR'
        }
        {
            $ruleType = 'ShutdownOnError'
        }
        # view any database
        {
            $PSItem -match "Obtain the list of roles that are authorized for the SQL Server 'View any database'"
        }
        {
            $ruleType = 'ViewAnyDatabase'
        }
        # db owner
        {
            $PSItem -match 'SQL Server accounts authorized to own database'
        }
        {
            $ruleType = 'ChangeDatabaseOwner'
        }
        <#
            Default parser if not caught before now - if we end up here we haven't trapped for the rule sub-type.
            These should be able to get, test, set via Get-Query cleanly
        #>
        default
        {
            $ruleType = 'PlainSQL'
        }
    }

    return $ruleType
}

<#
    .SYNOPSIS
        Determines if a SQL rule requires a variable to 
#>
function Test-VariableRequired
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $Rule
    )

    $requiresVariableList = @(
        'V-41037'
        'V-41024'
        'V-41022'
        'V-41251'
        'V-41407'
    )

    return ($Rule -in $requiresVariableList)
}
#endregion Helper Functions
