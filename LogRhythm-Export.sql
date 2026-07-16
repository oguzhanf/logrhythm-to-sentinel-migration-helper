/* ============================================================================
   LogRhythm 7.x -> Microsoft Sentinel Migration Helper
   Read-only T-SQL export of EMDB configuration data.
   Target engine : SQL Server on the LogRhythm Platform Manager.
   Standard LogRhythm 7.x schema (EMDB).
   ============================================================================

   PURPOSE
   -------
   Produces result sets that map directly to Sentinel onboarding artifacts:
     Section 0  Schema/table discovery  -- verify names on your build first
     Section 1  Entity inventory        -- Sentinel workspace / resource-group scope
     Section 2  Host inventory          -- Azure Arc / MDE onboarding scope
     Section 3  Log Source inventory    -- Sentinel Data Connector mapping
     Section 4  Log Source Type counts  -- connector prioritisation
     Section 5  AIE Rule inventory      -- Analytics Rule conversion backlog
     Section 6  Alarm Rule inventory    -- Automation Rule / Playbook backlog

   REQUIREMENTS
   ------------
   * SQL Server Management Studio (SSMS) 18 or later recommended.
   * Read-only SELECT access to the EMDB on the Platform Manager SQL Server.
     No write, DDL, or elevated permissions are required.
   * This script makes NO data changes.

   HOW TO RUN IN SSMS
   ------------------
   1. In SSMS Object Explorer, connect to the Platform Manager SQL Server.
   2. Open this file: File > Open > File...
   3. If your EMDB has a non-default name, update the USE statement below
      (search for the label: CHANGE DB NAME HERE).
   4. Set output to grid mode: Query > Results To > Results to Grid (Ctrl+D).
   5. Press F5 (or click Execute) to run all batches.
   6. Each numbered section produces a separate result tab.
      To save: right-click the result grid > Save Results As... > CSV.
      Suggested file names:
        00_schema_discovery.csv
        01_entities.csv
        02_hosts.csv
        03_log_sources.csv
        04_log_source_type_counts.csv
        05_aie_rules.csv          (populated only when AIE table is present)
        06_alarm_rules.csv        (populated only when Alarm table is present)
   7. Alternatively, run Invoke-LogRhythmSentinelMigration.ps1 (same folder)
      with -Action Export to
      write all CSVs automatically.

   !! IMPORTANT - AIE RULE LOGIC MUST ALSO BE EXPORTED FROM THE CONSOLE !!
   -------------------------------------------------------------------------
   Section 5 captures AIE Rule METADATA only (name, description, enabled
   flag, severity, etc.).  Full detection logic -- sub-rules, filter
   criteria, correlation blocks, threshold values -- is NOT stored in
   plain SQL columns and MUST be exported separately from the Console:

     LogRhythm Console
       > Deployment Manager > AI Engine Rules
       > Select All  >  File > Export to XML

   Store the exported XML alongside the CSVs produced by this script.
   The XML is required to recreate rule bodies as Microsoft Sentinel
   Analytics Rules (KQL).  Without it you will have rule names but no
   rule logic.

   ============================================================================ */


/* ============================================================================
   DATABASE CONTEXT
   Change "LogRhythmEMDB" if your EMDB database has a non-default name.
   ============================================================================ */
USE LogRhythmEMDB;   -- CHANGE DB NAME HERE IF DIFFERENT
GO

PRINT '============================================================';
PRINT ' LogRhythm EMDB Export  --  started: '
    + CONVERT(varchar(23), GETDATE(), 120);
PRINT '============================================================';
GO


/* ============================================================================
   SECTION 0: SCHEMA / TABLE DISCOVERY
   Always run this section first.  It lists every relevant table found on
   your specific LogRhythm build, with column names and data types.
   Use it to verify table names before consuming the downstream result sets,
   and to spot any schema differences from the standard 7.x layout.
   ============================================================================ */
PRINT '';
PRINT 'Section 0: Schema/Table Discovery';

SELECT
    t.name                                              AS TableName,
    c.column_id                                         AS ColOrder,
    c.name                                              AS ColumnName,
    tp.name                                             AS DataType,
    CASE
        WHEN tp.name IN ('varchar', 'nvarchar', 'char', 'nchar')
            THEN tp.name + '('
               + CASE c.max_length
                     WHEN -1 THEN 'MAX'
                     ELSE CAST(
                              CASE WHEN tp.name IN ('nvarchar', 'nchar')
                                   THEN c.max_length / 2
                                   ELSE c.max_length
                              END AS varchar(10))
                 END + ')'
        WHEN tp.name IN ('decimal', 'numeric')
            THEN tp.name + '('
               + CAST(c.precision AS varchar(5))
               + ',' + CAST(c.scale    AS varchar(5)) + ')'
        ELSE tp.name
    END                                                 AS FullDataType,
    c.is_nullable                                       AS IsNullable,
    c.is_identity                                       AS IsIdentity
FROM      sys.tables  t
JOIN      sys.columns c  ON t.object_id    = c.object_id
JOIN      sys.types   tp ON c.user_type_id = tp.user_type_id
WHERE t.name IN (
    'Entity', 'Host', 'MsgSource', 'LogSource', 'MsgSourceType',
    'AIERule', 'AlarmRule', 'MPERule', 'Network',
    'SystemMonitorPolicy', 'LogSourceVirtualSource'
)
   OR t.name LIKE '%LogSource%'
   OR t.name LIKE '%MsgSource%'
   OR t.name LIKE '%AIE%'
   OR t.name LIKE '%Alarm%'
   OR t.name LIKE '%Entity%'
   OR t.name LIKE '%Host%'
ORDER BY t.name, c.column_id;
GO


/* ============================================================================
   SECTION 1: ENTITY INVENTORY
   LogRhythm Entities represent logical security zones or organisational units
   (e.g. business divisions, sites).  Use this list to define the scope for
   Microsoft Sentinel workspaces, resource groups, and RBAC assignments.
   ============================================================================ */
PRINT '';
PRINT 'Section 1: Entity Inventory';

SELECT *
FROM   dbo.Entity
ORDER BY Name;
GO


/* ============================================================================
   SECTION 2: HOST INVENTORY
   Every host (server, workstation, network device) registered in LogRhythm,
   with its parent Entity.  Use to scope Azure Arc enrollment and Defender
   for Endpoint onboarding, and to map hostname-to-entity relationships.
   ============================================================================ */
PRINT '';
PRINT 'Section 2: Host Inventory';

SELECT
    h.*,
    e.Name  AS EntityName
FROM   dbo.Host    h
LEFT JOIN dbo.Entity e ON h.EntityID = e.EntityID
ORDER BY e.Name, h.Name;
GO


/* ============================================================================
   SECTION 3: LOG SOURCE INVENTORY
   Every log source registered in LogRhythm, joined to its host, entity, and
   source type.  This is the primary table for Sentinel Data Connector mapping:
   one LogRhythm log source typically maps to one Sentinel connector or custom
   parser (DCR / CEF / Syslog / AMA agent).
   ============================================================================ */
PRINT '';
PRINT 'Section 3: Log Source Inventory';

DECLARE @LogSourceObject nvarchar(517) =
    CASE
        WHEN OBJECT_ID(N'dbo.MsgSource', N'U') IS NOT NULL
            THEN N'[dbo].[MsgSource]'
        WHEN OBJECT_ID(N'dbo.LogSource', N'U') IS NOT NULL
            THEN N'[dbo].[LogSource]'
        ELSE NULL
    END;

IF @LogSourceObject IS NULL
    PRINT 'NOTICE: Neither dbo.MsgSource nor dbo.LogSource was found. Check Section 0 results.';
ELSE
BEGIN
    DECLARE @LogSourceSql nvarchar(max) = N'
        SELECT
            e.Name   AS Entity,
            h.Name   AS HostName,
            mst.Name AS LogSourceType,
            ls.*
        FROM ' + @LogSourceObject + N' AS ls
        LEFT JOIN dbo.Host          AS h   ON ls.HostID          = h.HostID
        LEFT JOIN dbo.Entity        AS e   ON h.EntityID         = e.EntityID
        LEFT JOIN dbo.MsgSourceType AS mst ON ls.MsgSourceTypeID = mst.MsgSourceTypeID
        ORDER BY mst.Name, e.Name, h.Name;';
    EXEC sys.sp_executesql @LogSourceSql;
END;
GO


/* ============================================================================
   SECTION 4: LOG SOURCE TYPE COUNTS
   Number of log sources per type, sorted by volume descending.
   Use to prioritise which Sentinel Data Connectors or custom parsers (KQL
   parser functions / ASIM normalisers) to build or configure first.
   ============================================================================ */
PRINT '';
PRINT 'Section 4: Log Source Type Counts';

DECLARE @LogSourceObject nvarchar(517) =
    CASE
        WHEN OBJECT_ID(N'dbo.MsgSource', N'U') IS NOT NULL
            THEN N'[dbo].[MsgSource]'
        WHEN OBJECT_ID(N'dbo.LogSource', N'U') IS NOT NULL
            THEN N'[dbo].[LogSource]'
        ELSE NULL
    END;

IF @LogSourceObject IS NULL
    PRINT 'NOTICE: Neither dbo.MsgSource nor dbo.LogSource was found. Check Section 0 results.';
ELSE
BEGIN
    DECLARE @LogSourceSql nvarchar(max) = N'
        SELECT
            mst.Name AS LogSourceType,
            COUNT(*) AS LogSourceCount
        FROM ' + @LogSourceObject + N' AS ls
        LEFT JOIN dbo.MsgSourceType AS mst ON ls.MsgSourceTypeID = mst.MsgSourceTypeID
        GROUP BY mst.Name
        ORDER BY COUNT(*) DESC;';
    EXEC sys.sp_executesql @LogSourceSql;
END;
GO


/* ============================================================================
   SECTION 5: AIE RULE INVENTORY  (guarded - skipped if table is absent)
   AI Engine rules are the nearest equivalent to Sentinel Analytics Rules.

   !! METADATA ONLY -- see the AIE RULE LOGIC warning in the file header !!
   Full rule logic must ALSO be exported from the LogRhythm Console as XML.
   ============================================================================ */
PRINT '';
PRINT 'Section 5: AIE Rule Inventory';

IF OBJECT_ID('dbo.AIERule', 'U') IS NOT NULL
    EXEC sp_executesql N'SELECT * FROM dbo.AIERule;';
ELSE
    PRINT 'NOTICE: dbo.AIERule was not found on this build. '
        + 'The table may be absent or named differently. '
        + 'Check Section 0 results for the actual table name, '
        + 'then adjust this query accordingly.';
GO


/* ============================================================================
   SECTION 6: ALARM RULE INVENTORY  (guarded - skipped if table is absent)
   Alarm Rules define when LogRhythm escalates an AIE event or log match into
   a visible alarm.  Map to Sentinel Automation Rules and Logic App Playbooks.
   ============================================================================ */
PRINT '';
PRINT 'Section 6: Alarm Rule Inventory';

IF OBJECT_ID('dbo.AlarmRule', 'U') IS NOT NULL
    EXEC sp_executesql N'SELECT * FROM dbo.AlarmRule;';
ELSE
    PRINT 'NOTICE: dbo.AlarmRule was not found on this build. '
        + 'The table may be absent or named differently. '
        + 'Check Section 0 results for the actual table name, '
        + 'then adjust this query accordingly.';
GO


PRINT '';
PRINT '============================================================';
PRINT ' LogRhythm EMDB Export  --  completed: '
    + CONVERT(varchar(23), GETDATE(), 120);
PRINT ' Save each result tab as CSV before closing SSMS.';
PRINT ' Remember to export AIE rule XML from the LogRhythm Console.';
PRINT '============================================================';
