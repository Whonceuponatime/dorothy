using System;
using System.Collections.Generic;
using System.Data.Common;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Threading.Tasks;
using Dorothy.Models;
using Dorothy.Models.Database;
using Microsoft.Data.Sqlite;
using NLog;

namespace Dorothy.Services
{
    public class DatabaseService : IDisposable
    {
        private static readonly ILogger Logger = LogManager.GetCurrentClassLogger();
        private readonly string _dbPath;
        private readonly string _connectionString;
        private bool _disposed = false;

        public DatabaseService()
        {
            var appDataPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "Dorothy"
            );
            Directory.CreateDirectory(appDataPath);
            _dbPath = Path.Combine(appDataPath, "dorothy.db");
            _connectionString = $"Data Source={_dbPath}";

            CheckAndRecreateDatabaseIfNeeded();

            InitializeDatabase();
        }

        private void CheckAndRecreateDatabaseIfNeeded()
        {
            // 2.6.0 engagement-evidence migration. Two failure modes the previous
            // implementation missed:
            //   1. CREATE TABLE IF NOT EXISTS is a no-op against legacy tables —
            //      the new EngagementId column never lands, then CREATE INDEX …
            //      (EngagementId) blows up with "no such column".
            //   2. File.Delete fights Microsoft.Data.Sqlite's connection pool;
            //      the file lock often outlives `using var` scope, so deletion
            //      silently fails on the last retry.
            // Fix: detect both "Engagements absent" AND "Engagements present but
            // legacy tables lack EngagementId", then DROP the legacy tables via
            // SQL (sidesteps the pool entirely). InitializeDatabase recreates.
            try
            {
                if (!File.Exists(_dbPath))
                {
                    Logger.Info("[DB] Fresh install — engagement schema will be created.");
                    return;
                }

                bool needsLegacyDrop = false;
                try
                {
                    using var probeConn = new SqliteConnection(_connectionString);
                    probeConn.Open();

                    // Three flavours of legacy schema all need a wipe:
                    //   pre-2.6.0 — no Engagements table at all
                    //   first 2.6.0 — Engagements + Assets without nullable
                    //                 EngagementId
                    //   second 2.6.0 — has SessionId column (now removed in
                    //                  favour of EngagementId IS NULL filter)
                    //   third 2.6.0 — missing TopologyNodes table (offline rework)
                    var checkEng = probeConn.CreateCommand();
                    checkEng.CommandText =
                        "SELECT name FROM sqlite_master WHERE type='table' AND name='Engagements'";
                    bool hasEngagements = checkEng.ExecuteScalar() != null;

                    if (!hasEngagements)
                    {
                        needsLegacyDrop = true;
                    }
                    else
                    {
                        var checkAssetsCol = probeConn.CreateCommand();
                        checkAssetsCol.CommandText = "PRAGMA table_info(Assets)";
                        bool hasAssets = false, hasEngagementIdOnAssets = false, hasSessionIdOnAssets = false;
                        using (var rdr = checkAssetsCol.ExecuteReader())
                        {
                            while (rdr.Read())
                            {
                                hasAssets = true;
                                var col = rdr.GetString(1);
                                if (col == "EngagementId") hasEngagementIdOnAssets = true;
                                else if (col == "SessionId") hasSessionIdOnAssets = true;
                            }
                        }
                        if (hasAssets && (!hasEngagementIdOnAssets || hasSessionIdOnAssets))
                            needsLegacyDrop = true;

                        if (!needsLegacyDrop)
                        {
                            // Confirm offline rework's topology tables landed.
                            var checkTopo = probeConn.CreateCommand();
                            checkTopo.CommandText =
                                "SELECT name FROM sqlite_master WHERE type='table' AND name='TopologyNodes'";
                            if (checkTopo.ExecuteScalar() == null) needsLegacyDrop = true;
                        }
                    }
                }
                catch (Exception ex)
                {
                    Logger.Warn(ex, "[DB] Could not inspect existing schema — assuming wipe is needed.");
                    needsLegacyDrop = true;
                }

                if (!needsLegacyDrop) return;

                Logger.Info("[DB] Detected legacy schema (pre-engagement). Backing up + dropping legacy tables.");

                // Backup BEFORE mutation, with timestamp so repeated upgrades don't overwrite.
                var backupPath = Path.Combine(
                    Path.GetDirectoryName(_dbPath)!,
                    $"dorothy_pre_engagement_{DateTime.UtcNow:yyyyMMdd_HHmmss}.db");
                try
                {
                    File.Copy(_dbPath, backupPath, overwrite: false);
                    Logger.Info($"[DB] Backed up legacy database to: {backupPath}");
                }
                catch (Exception ex)
                {
                    Logger.Warn(ex, "[DB] Backup failed; proceeding with table drops anyway.");
                }

                // DROP legacy tables in place. This avoids the connection-pool /
                // file-lock fight that File.Delete loses against Microsoft.Data.Sqlite.
                try
                {
                    using var dropConn = new SqliteConnection(_connectionString);
                    dropConn.Open();
                    var drop = dropConn.CreateCommand();
                    drop.CommandText = @"
                        DROP TABLE IF EXISTS Assets;
                        DROP TABLE IF EXISTS Ports;
                        DROP TABLE IF EXISTS AttackLogs;
                        DROP TABLE IF EXISTS reachability_runs;
                        DROP TABLE IF EXISTS TopologyNodes;
                        DROP TABLE IF EXISTS TopologyEdges;
                        DROP TABLE IF EXISTS TopologySubnets;
                        DROP TABLE IF EXISTS TraceroutePaths;
                    ";
                    drop.ExecuteNonQuery();
                    Logger.Info("[DB] Legacy tables dropped. InitializeDatabase will now create the engagement schema.");
                }
                catch (Exception ex)
                {
                    Logger.Error(ex, "[DB] DROP TABLE failed. Falling back to file delete.");
                    SqliteConnection.ClearAllPools();
                    GC.Collect();
                    GC.WaitForPendingFinalizers();
                    System.Threading.Thread.Sleep(100);
                    try { if (File.Exists(_dbPath)) File.Delete(_dbPath); }
                    catch (Exception delEx)
                    {
                        Logger.Error(delEx, "[DB] File delete also failed. User may need to manually delete the DB.");
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "[DB] Engagement schema migration check failed");
            }
        }

        // 2.2.7-era HardwareId migration retained as historical reference but
        // never invoked from the live path. Kept commented out below to make
        // the intent obvious in a code review without keeping unreachable code.
        #pragma warning disable CS0162
        private void LegacyTwoTwoSeven_DEAD()
        {
            try
            {
                var currentVersion = System.Reflection.Assembly.GetExecutingAssembly().GetName().Version;
                if (currentVersion == null || currentVersion.Major != 2 || currentVersion.Minor != 2 || currentVersion.Build != 7)
                {

                    Logger.Info($"Skipping database recreation check - not version 2.2.7 (current: {currentVersion?.Major}.{currentVersion?.Minor}.{currentVersion?.Build})");
                    return;
                }

                Logger.Info("Version 2.2.7: Checking database schema for required columns...");

                if (!File.Exists(_dbPath))
                {

                    Logger.Info("Database file does not exist - will be created with correct schema.");
                    return;
                }

                bool needsRecreation = false;
                SqliteConnection? checkConnection = null;
                try
                {
                    checkConnection = new SqliteConnection(_connectionString);
                    checkConnection.Open();

                    bool assetsNeedsRecreation = false;
                    try
                    {
                        var checkAssets = checkConnection.CreateCommand();
                        checkAssets.CommandText = "PRAGMA table_info(Assets)";
                        var assetsColumns = new HashSet<string>();
                        using (var assetsReader = checkAssets.ExecuteReader())
                        {
                            while (assetsReader.Read())
                            {
                                assetsColumns.Add(assetsReader.GetString(1));
                            }
                        }
                        if (!assetsColumns.Contains("HardwareId"))
                        {
                            assetsNeedsRecreation = true;
                        }
                    }
                    catch
                    {

                        assetsNeedsRecreation = true;
                    }

                    bool portsNeedsRecreation = false;
                    try
                    {
                        var checkPorts = checkConnection.CreateCommand();
                        checkPorts.CommandText = "SELECT name FROM sqlite_master WHERE type='table' AND name='Ports'";
                        var portsTableExists = checkPorts.ExecuteScalar() != null;

                        if (portsTableExists)
                        {
                            checkPorts.CommandText = "PRAGMA table_info(Ports)";
                            var portsColumns = new HashSet<string>();
                            using (var portsReader = checkPorts.ExecuteReader())
                            {
                                while (portsReader.Read())
                                {
                                    portsColumns.Add(portsReader.GetString(1));
                                }
                            }
                            if (!portsColumns.Contains("HardwareId"))
                            {
                                portsNeedsRecreation = true;
                            }
                        }
                    }
                    catch
                    {

                        portsNeedsRecreation = true;
                    }

                    bool attackLogsNeedsRecreation = false;
                    try
                    {
                        var checkAttackLogs = checkConnection.CreateCommand();
                        checkAttackLogs.CommandText = "SELECT name FROM sqlite_master WHERE type='table' AND name='AttackLogs'";
                        var attackLogsTableExists = checkAttackLogs.ExecuteScalar() != null;

                        if (attackLogsTableExists)
                        {
                            checkAttackLogs.CommandText = "PRAGMA table_info(AttackLogs)";
                            var attackLogsColumns = new HashSet<string>();
                            using (var attackLogsReader = checkAttackLogs.ExecuteReader())
                            {
                                while (attackLogsReader.Read())
                                {
                                    attackLogsColumns.Add(attackLogsReader.GetString(1));
                                }
                            }
                            if (!attackLogsColumns.Contains("HardwareId"))
                            {
                                attackLogsNeedsRecreation = true;
                            }
                        }
                    }
                    catch
                    {

                        attackLogsNeedsRecreation = true;
                    }

                    needsRecreation = assetsNeedsRecreation || portsNeedsRecreation || attackLogsNeedsRecreation;
                }
                catch (Exception checkEx)
                {
                    Logger.Warn(checkEx, "Error checking database schema - will attempt recreation as safety measure.");
                    needsRecreation = true;
                }
                finally
                {

                    if (checkConnection != null)
                    {
                        checkConnection.Close();
                        checkConnection.Dispose();
                    }
                }

                if (needsRecreation)
                {
                    Logger.Info("Version 2.2.7: Detected old database schema (missing HardwareId columns). Deleting and recreating database...");

                    var backupPath = _dbPath + ".backup." + DateTime.Now.ToString("yyyyMMddHHmmss");
                    try
                    {
                        if (File.Exists(_dbPath))
                        {
                            File.Copy(_dbPath, backupPath, true);
                            Logger.Info($"Backed up old database to: {backupPath}");
                        }
                    }
                    catch (Exception backupEx)
                    {
                        Logger.Warn(backupEx, "Failed to backup database, proceeding with deletion anyway.");
                    }

                    GC.Collect();
                    GC.WaitForPendingFinalizers();
                    System.Threading.Thread.Sleep(100);

                    int retries = 5;
                    bool deleted = false;
                    for (int i = 0; i < retries && !deleted; i++)
                    {
                        try
                        {
                            if (File.Exists(_dbPath))
                            {
                                File.Delete(_dbPath);
                                deleted = true;
                                Logger.Info("Successfully deleted old database. New database will be created with correct schema.");
                            }
                            else
                            {
                                deleted = true;
                            }
                        }
                        catch (Exception deleteEx)
                        {
                            if (i < retries - 1)
                            {
                                Logger.Warn($"Failed to delete database (attempt {i + 1}/{retries}), retrying in 500ms...");
                                System.Threading.Thread.Sleep(500);
                            }
                            else
                            {
                                Logger.Error(deleteEx, "Failed to delete old database after multiple attempts. User may need to manually delete the database file.");

                            }
                        }
                    }
                }
                else
                {
                    Logger.Info("Database schema check passed - all required columns present.");
                }
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "Failed to check/recreate database for version 2.2.7. Will attempt to delete and recreate anyway.");

                try
                {
                    if (File.Exists(_dbPath))
                    {
                        GC.Collect();
                        GC.WaitForPendingFinalizers();
                        System.Threading.Thread.Sleep(200);
                        File.Delete(_dbPath);
                        Logger.Info("Deleted database file as safety measure. New database will be created.");
                    }
                }
                catch (Exception deleteEx)
                {
                    Logger.Warn(deleteEx, "Could not delete database file. Migration will attempt to add missing columns.");
                }
            }
            #pragma warning restore CS0162
        }

        private void MigrateDatabase(SqliteConnection connection)
        {
            try
            {

                try
                {
                    var dropReachabilityTables = connection.CreateCommand();
                    dropReachabilityTables.CommandText = @"
                        DROP TABLE IF EXISTS ReachabilityIcmpResults;
                        DROP TABLE IF EXISTS ReachabilityTcpResults;
                        DROP TABLE IF EXISTS ReachabilityPathHops;
                        DROP TABLE IF EXISTS ReachabilityDeeperScans;
                        DROP TABLE IF EXISTS ReachabilitySnmpWalks;
                        DROP TABLE IF EXISTS ReachabilityTests;
                    ";
                    dropReachabilityTables.ExecuteNonQuery();
                }
                catch (Exception ex)
                {
                    Logger.Warn(ex, "Failed to drop legacy reachability tables - continuing");
                }

                var checkTableExists = connection.CreateCommand();
                checkTableExists.CommandText = @"
                    SELECT name FROM sqlite_master
                    WHERE type='table' AND name='Assets';
                ";
                var assetsTableExists = checkTableExists.ExecuteScalar() != null;

                if (!assetsTableExists)
                {
                    Logger.Info("Assets table does not exist yet - will be created with all columns");
                }
                else
                {

                    var columns = new HashSet<string>();
                    try
                    {
                        var checkCommand = connection.CreateCommand();
                        checkCommand.CommandText = "PRAGMA table_info(Assets)";

                        using (var reader = checkCommand.ExecuteReader())
                        {
                            while (reader.Read())
                            {
                                columns.Add(reader.GetString(1));
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        Logger.Warn(ex, "Failed to check Assets table columns, will attempt to add all columns");

                        columns.Clear();
                    }

                    var assetsColumnsToAdd = new[] { "HardwareId", "MachineName", "Username", "UserId", "Ports" };
                    foreach (var columnName in assetsColumnsToAdd)
                    {

                        try
                        {
                            var addColumn = connection.CreateCommand();
                            addColumn.CommandText = $"ALTER TABLE Assets ADD COLUMN {columnName} TEXT";
                            addColumn.ExecuteNonQuery();
                            Logger.Info($"Successfully added {columnName} column to Assets table");
                        }
                        catch (Microsoft.Data.Sqlite.SqliteException sqlEx) when (sqlEx.Message.Contains("duplicate column") || sqlEx.Message.Contains("already exists") || sqlEx.SqliteErrorCode == 1)
                        {

                            Logger.Debug($"{columnName} column already exists in Assets table");
                        }
                        catch (Exception ex)
                        {
                            Logger.Warn(ex, $"Failed to add {columnName} column to Assets table (may already exist)");

                        }
                    }
                }

                var checkPortsTableExists = connection.CreateCommand();
                checkPortsTableExists.CommandText = @"
                    SELECT name FROM sqlite_master
                    WHERE type='table' AND name='Ports';
                ";
                var portsTableExists = checkPortsTableExists.ExecuteScalar() != null;

                if (portsTableExists)
                {
                    var portsColumns = new HashSet<string>();
                    try
                    {
                        var portsCheckCommand = connection.CreateCommand();
                        portsCheckCommand.CommandText = "PRAGMA table_info(Ports)";

                        using (var portsReader = portsCheckCommand.ExecuteReader())
                        {
                            while (portsReader.Read())
                            {
                                portsColumns.Add(portsReader.GetString(1));
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        Logger.Warn(ex, "Failed to check Ports table columns, will attempt to add all columns");

                        portsColumns.Clear();
                    }

                    var columnsToAdd = new[] { "HardwareId", "MachineName", "Username", "UserId" };
                    foreach (var columnName in columnsToAdd)
                    {
                        if (!portsColumns.Contains(columnName))
                        {
                            Logger.Info($"Migrating Ports table: Adding {columnName} column");
                            try
                            {
                                var addColumn = connection.CreateCommand();
                                addColumn.CommandText = $"ALTER TABLE Ports ADD COLUMN {columnName} TEXT";
                                addColumn.ExecuteNonQuery();
                                Logger.Info($"Successfully added {columnName} column to Ports table");
                            }
                            catch (Microsoft.Data.Sqlite.SqliteException sqlEx) when (sqlEx.Message.Contains("duplicate column") || sqlEx.Message.Contains("already exists"))
                            {

                                Logger.Info($"{columnName} column already exists in Ports table");
                            }
                            catch (Exception ex)
                            {
                                Logger.Error(ex, $"Failed to add {columnName} column to Ports table");

                            }
                        }
                    }
                }
                else
                {
                    Logger.Info("Ports table does not exist yet - will be created with all columns");
                }

                var checkAttackLogsTableExists = connection.CreateCommand();
                checkAttackLogsTableExists.CommandText = @"
                    SELECT name FROM sqlite_master
                    WHERE type='table' AND name='AttackLogs';
                ";
                var attackLogsTableExists = checkAttackLogsTableExists.ExecuteScalar() != null;

                if (attackLogsTableExists)
                {
                    var attackLogsColumns = new HashSet<string>();
                    try
                    {
                        var attackLogsCheckCommand = connection.CreateCommand();
                        attackLogsCheckCommand.CommandText = "PRAGMA table_info(AttackLogs)";

                        using (var attackLogsReader = attackLogsCheckCommand.ExecuteReader())
                        {
                            while (attackLogsReader.Read())
                            {
                                attackLogsColumns.Add(attackLogsReader.GetString(1));
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        Logger.Warn(ex, "Failed to check AttackLogs table columns, will attempt to add all columns");

                        attackLogsColumns.Clear();
                    }

                    var attackLogsColumnsToAdd = new[] { "HardwareId", "MachineName", "Username", "UserId" };
                    foreach (var columnName in attackLogsColumnsToAdd)
                    {

                        try
                        {
                            var addColumn = connection.CreateCommand();
                            addColumn.CommandText = $"ALTER TABLE AttackLogs ADD COLUMN {columnName} TEXT";
                            addColumn.ExecuteNonQuery();
                            Logger.Info($"Successfully added {columnName} column to AttackLogs table");
                        }
                        catch (Microsoft.Data.Sqlite.SqliteException sqlEx) when (sqlEx.Message.Contains("duplicate column") || sqlEx.Message.Contains("already exists") || sqlEx.SqliteErrorCode == 1)
                        {

                            Logger.Debug($"{columnName} column already exists in AttackLogs table");
                        }
                        catch (Exception ex)
                        {
                            Logger.Warn(ex, $"Failed to add {columnName} column to AttackLogs table (may already exist)");

                        }
                    }
                }
                else
                {
                    Logger.Info("AttackLogs table does not exist yet - will be created with all columns");
                }

                Logger.Info("Database migration completed successfully");
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "Error during database migration");

            }
        }

        private void InitializeDatabase()
        {
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                connection.Open();

                var command = connection.CreateCommand();
                command.CommandText = @"
                    CREATE TABLE IF NOT EXISTS Engagements (
                        Id INTEGER PRIMARY KEY AUTOINCREMENT,
                        RemoteId TEXT,
                        Name TEXT NOT NULL,
                        ClientName TEXT,
                        Scope TEXT,
                        StartedAt TEXT NOT NULL,
                        EndedAt TEXT,
                        Status TEXT NOT NULL,
                        SurveyorHardwareId TEXT NOT NULL,
                        SurveyorEmail TEXT,
                        Notes TEXT,
                        CreatedAt TEXT NOT NULL,
                        SubmittedAt TEXT
                    );
                    CREATE INDEX IF NOT EXISTS idx_engagements_status_hwid
                        ON Engagements(Status, SurveyorHardwareId);

                    CREATE TABLE IF NOT EXISTS AttackLogs (
                        Id INTEGER PRIMARY KEY AUTOINCREMENT,
                        EngagementId INTEGER,
                        AttackType TEXT NOT NULL,
                        Protocol TEXT NOT NULL,
                        SourceIp TEXT NOT NULL,
                        SourceMac TEXT,
                        TargetIp TEXT NOT NULL,
                        TargetMac TEXT,
                        TargetPort INTEGER NOT NULL DEFAULT 0,
                        TargetRateMbps REAL NOT NULL,
                        PacketsSent INTEGER NOT NULL DEFAULT 0,
                        DurationSeconds INTEGER NOT NULL DEFAULT 0,
                        StartTime TEXT NOT NULL,
                        StopTime TEXT NOT NULL,
                        Note TEXT,
                        LogContent TEXT NOT NULL,
                        CreatedAt TEXT NOT NULL,
                        HardwareId TEXT,
                        MachineName TEXT,
                        Username TEXT,
                        UserId TEXT,
                        FOREIGN KEY (EngagementId) REFERENCES Engagements(Id)
                    );
                    CREATE INDEX IF NOT EXISTS idx_attacklogs_engagement
                        ON AttackLogs(EngagementId);

                    CREATE TABLE IF NOT EXISTS Assets (
                        Id INTEGER PRIMARY KEY AUTOINCREMENT,
                        EngagementId INTEGER,
                        HostIp TEXT NOT NULL,
                        HostName TEXT,
                        MacAddress TEXT,
                        Vendor TEXT,
                        IsOnline INTEGER NOT NULL DEFAULT 0,
                        PingTime INTEGER,
                        ScanTime TEXT NOT NULL,
                        CreatedAt TEXT NOT NULL,
                        HardwareId TEXT,
                        MachineName TEXT,
                        Username TEXT,
                        UserId TEXT,
                        Ports TEXT,
                        IndustrialVendor TEXT,
                        IndustrialCategory TEXT,
                        IndustrialProtocols TEXT,
                        FOREIGN KEY (EngagementId) REFERENCES Engagements(Id)
                    );
                    CREATE INDEX IF NOT EXISTS idx_assets_engagement
                        ON Assets(EngagementId);

                    CREATE TABLE IF NOT EXISTS Ports (
                        Id INTEGER PRIMARY KEY AUTOINCREMENT,
                        EngagementId INTEGER,
                        AssetId INTEGER,
                        HostIp TEXT NOT NULL,
                        Port INTEGER NOT NULL,
                        Protocol TEXT NOT NULL DEFAULT 'TCP',
                        Service TEXT,
                        Banner TEXT,
                        ScanTime TEXT NOT NULL,
                        CreatedAt TEXT NOT NULL,
                        HardwareId TEXT,
                        MachineName TEXT,
                        Username TEXT,
                        UserId TEXT,
                        FOREIGN KEY (AssetId) REFERENCES Assets(Id) ON DELETE CASCADE,
                        FOREIGN KEY (EngagementId) REFERENCES Engagements(Id)
                    );
                    CREATE INDEX IF NOT EXISTS idx_ports_engagement
                        ON Ports(EngagementId);

                    CREATE TABLE IF NOT EXISTS reachability_runs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        EngagementId INTEGER,
                        started_at TEXT NOT NULL,
                        completed_at TEXT,
                        label TEXT,
                        source_ip TEXT,
                        source_nic TEXT,
                        target_raw TEXT,
                        results_json TEXT,
                        hosts_tested INTEGER DEFAULT 0,
                        hosts_reachable INTEGER DEFAULT 0,
                        hosts_partial INTEGER DEFAULT 0,
                        hosts_unreachable INTEGER DEFAULT 0,
                        hosts_no_route INTEGER DEFAULT 0
                    );

                    -- 2.6.0 offline-persistence rework: topology now lives in DB.
                    -- Loaded on launch so the canvas renders without waiting for
                    -- a fresh discovery sweep. Surveyor scans offline at sea,
                    -- closes Dorothy, reopens days later in port, submits.
                    CREATE TABLE IF NOT EXISTS TopologyNodes (
                        Id INTEGER PRIMARY KEY AUTOINCREMENT,
                        NodeId TEXT NOT NULL,
                        NodeType TEXT NOT NULL,
                        Ip TEXT,
                        Mac TEXT,
                        Vendor TEXT,
                        Hostname TEXT,
                        Attributes TEXT,
                        EngagementId INTEGER,
                        DiscoveredAt TEXT NOT NULL,
                        LastUpdatedAt TEXT NOT NULL,
                        FOREIGN KEY (EngagementId) REFERENCES Engagements(Id)
                    );
                    CREATE INDEX IF NOT EXISTS idx_topo_nodes_engagement
                        ON TopologyNodes(EngagementId);
                    CREATE UNIQUE INDEX IF NOT EXISTS idx_topo_nodes_node_id_unsubmitted
                        ON TopologyNodes(NodeId) WHERE EngagementId IS NULL;

                    CREATE TABLE IF NOT EXISTS TopologyEdges (
                        Id INTEGER PRIMARY KEY AUTOINCREMENT,
                        SourceNodeId TEXT NOT NULL,
                        TargetNodeId TEXT NOT NULL,
                        EdgeType TEXT NOT NULL,
                        Attributes TEXT,
                        EngagementId INTEGER,
                        DiscoveredAt TEXT NOT NULL,
                        FOREIGN KEY (EngagementId) REFERENCES Engagements(Id)
                    );
                    CREATE INDEX IF NOT EXISTS idx_topo_edges_engagement
                        ON TopologyEdges(EngagementId);
                    CREATE UNIQUE INDEX IF NOT EXISTS idx_topo_edges_unsubmitted
                        ON TopologyEdges(SourceNodeId, TargetNodeId, EdgeType)
                        WHERE EngagementId IS NULL;

                    CREATE TABLE IF NOT EXISTS TopologySubnets (
                        Id INTEGER PRIMARY KEY AUTOINCREMENT,
                        SubnetCidr TEXT NOT NULL,
                        Network TEXT,
                        IsLocal INTEGER NOT NULL,
                        IsInternet INTEGER NOT NULL,
                        EngagementId INTEGER,
                        DiscoveredAt TEXT NOT NULL,
                        FOREIGN KEY (EngagementId) REFERENCES Engagements(Id)
                    );
                    CREATE INDEX IF NOT EXISTS idx_topo_subnets_engagement
                        ON TopologySubnets(EngagementId);

                    CREATE TABLE IF NOT EXISTS TraceroutePaths (
                        Id INTEGER PRIMARY KEY AUTOINCREMENT,
                        Target TEXT NOT NULL,
                        HopOrder INTEGER NOT NULL,
                        HopIp TEXT,
                        RttMs INTEGER,
                        EngagementId INTEGER,
                        DiscoveredAt TEXT NOT NULL,
                        FOREIGN KEY (EngagementId) REFERENCES Engagements(Id)
                    );
                    CREATE INDEX IF NOT EXISTS idx_trace_engagement
                        ON TraceroutePaths(EngagementId);
                ";
                command.ExecuteNonQuery();
                Logger.Info("Database tables created");

                MigrateDatabase(connection);

                Logger.Info("Database initialized successfully");
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "Failed to initialize database");
                throw;
            }
        }

        private async Task EnsureMigrationsAsync(SqliteConnection connection)
        {
            try
            {

                await Task.Run(() =>
                {
                    MigrateDatabase(connection);
                });
            }
            catch (Exception ex)
            {
                Logger.Warn(ex, "Failed to ensure migrations - continuing anyway");

            }
        }

        public async Task<long> SaveAttackLogAsync(AttackLogEntry entry)
        {
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();

                await EnsureMigrationsAsync(connection);

                var command = connection.CreateCommand();
                command.CommandText = @"
                    INSERT INTO AttackLogs
                    (EngagementId, AttackType, Protocol, SourceIp, SourceMac, TargetIp, TargetMac, TargetPort,
                     TargetRateMbps, PacketsSent, DurationSeconds, StartTime, StopTime, Note, LogContent, CreatedAt,
                     HardwareId, MachineName, Username, UserId)
                    VALUES
                    (NULL, @AttackType, @Protocol, @SourceIp, @SourceMac, @TargetIp, @TargetMac, @TargetPort,
                     @TargetRateMbps, @PacketsSent, @DurationSeconds, @StartTime, @StopTime, @Note, @LogContent, @CreatedAt,
                     @HardwareId, @MachineName, @Username, @UserId);
                    SELECT last_insert_rowid();
                ";

                command.Parameters.AddWithValue("@AttackType", entry.AttackType);
                command.Parameters.AddWithValue("@Protocol", entry.Protocol);
                command.Parameters.AddWithValue("@SourceIp", entry.SourceIp);
                command.Parameters.AddWithValue("@SourceMac", entry.SourceMac ?? (object)DBNull.Value);
                command.Parameters.AddWithValue("@TargetIp", entry.TargetIp);
                command.Parameters.AddWithValue("@TargetMac", entry.TargetMac ?? (object)DBNull.Value);
                command.Parameters.AddWithValue("@TargetPort", entry.TargetPort);
                command.Parameters.AddWithValue("@TargetRateMbps", entry.TargetRateMbps);
                command.Parameters.AddWithValue("@PacketsSent", entry.PacketsSent);
                command.Parameters.AddWithValue("@DurationSeconds", entry.DurationSeconds);
                command.Parameters.AddWithValue("@StartTime", entry.StartTime.ToString("O"));
                command.Parameters.AddWithValue("@StopTime", entry.StopTime.ToString("O"));
                command.Parameters.AddWithValue("@Note", entry.Note ?? (object)DBNull.Value);
                command.Parameters.AddWithValue("@LogContent", entry.LogContent);
                command.Parameters.AddWithValue("@CreatedAt", entry.CreatedAt.ToString("O"));
                command.Parameters.AddWithValue("@HardwareId", entry.HardwareId ?? (object)DBNull.Value);
                command.Parameters.AddWithValue("@MachineName", entry.MachineName ?? (object)DBNull.Value);
                command.Parameters.AddWithValue("@Username", entry.Username ?? (object)DBNull.Value);
                command.Parameters.AddWithValue("@UserId", entry.UserId?.ToString() ?? (object)DBNull.Value);

                var result = await command.ExecuteScalarAsync();
                return Convert.ToInt64(result);
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "Failed to save attack log");
                throw;
            }
        }

        // Removed in 2.6.0: GetUnsyncedLogsAsync — engagement-bundled submit replaces per-row sync flags.

        public async Task MarkAsSyncedAsync(long id, DateTime syncedAt)
        {
            await MarkAsSyncedAsync(new[] { id }, syncedAt);
        }

        public async Task MarkAsSyncedAsync(IEnumerable<long> ids, DateTime syncedAt)
        {
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();

                var idsList = ids.ToList();
                if (idsList.Count == 0) return;

                var placeholders = string.Join(",", idsList.Select((_, i) => $"@Id{i}"));
                var command = connection.CreateCommand();
                command.CommandText = $@"
                    UPDATE AttackLogs
                    SET IsSynced = 1, SyncedAt = @SyncedAt
                    WHERE Id IN ({placeholders})
                ";

                command.Parameters.AddWithValue("@SyncedAt", syncedAt.ToString("O"));
                for (int i = 0; i < idsList.Count; i++)
                {
                    command.Parameters.AddWithValue($"@Id{i}", idsList[i]);
                }

                await command.ExecuteNonQueryAsync();
            }
            catch (Exception ex)
            {
                Logger.Error(ex, $"Failed to mark logs as synced");
                throw;
            }
        }

        public async Task DeleteLogsAsync(IEnumerable<long> ids)
        {
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();

                var idsList = ids.ToList();
                if (idsList.Count == 0) return;

                var placeholders = string.Join(",", idsList.Select((_, i) => $"@Id{i}"));
                var command = connection.CreateCommand();
                command.CommandText = $@"
                    DELETE FROM AttackLogs
                    WHERE Id IN ({placeholders})
                ";

                for (int i = 0; i < idsList.Count; i++)
                {
                    command.Parameters.AddWithValue($"@Id{i}", idsList[i]);
                }

                await command.ExecuteNonQueryAsync();
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "Failed to delete logs");
                throw;
            }
        }

        public async Task<int> GetUnsyncedCountAsync()
        {
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();

                var command = connection.CreateCommand();
                command.CommandText = "SELECT COUNT(*) FROM AttackLogs WHERE IsSynced = 0";

                var result = await command.ExecuteScalarAsync();
                return Convert.ToInt32(result);
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "Failed to get unsynced count");
                return 0;
            }
        }

        public async Task<long?> GetAssetIdByHostIpAsync(string hostIp)
        {
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();

                var command = connection.CreateCommand();
                command.CommandText = "SELECT Id FROM Assets WHERE HostIp = @HostIp LIMIT 1";
                command.Parameters.AddWithValue("@HostIp", hostIp);

                var result = await command.ExecuteScalarAsync();
                if (result != null && result != DBNull.Value)
                {
                    return Convert.ToInt64(result);
                }
                return null;
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "Failed to get asset ID by host IP");
                return null;
            }
        }

        public async Task MarkAssetAsUnsyncedAsync(long assetId)
        {
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();

                var command = connection.CreateCommand();
                command.CommandText = @"
                    UPDATE Assets
                    SET Synced = 0, SyncedAt = NULL
                    WHERE Id = @AssetId
                ";
                command.Parameters.AddWithValue("@AssetId", assetId);

                await command.ExecuteNonQueryAsync();
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "Failed to mark asset as unsynced");
                throw;
            }
        }

        private async Task UpdateAssetPortsColumnAsync(long assetId, string hostIp)
        {
            try
            {

                var ports = await GetPortsByHostIpAsync(hostIp);

                string portsDisplay = null;
                if (ports != null && ports.Count > 0)
                {

                    portsDisplay = string.Join(", ", ports.OrderBy(p => p.Port).Select(p => $"{p.Port}/{p.Protocol}"));
                }

                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();

                var command = connection.CreateCommand();
                command.CommandText = @"
                    UPDATE Assets
                    SET Ports = @Ports
                    WHERE Id = @AssetId
                ";
                command.Parameters.AddWithValue("@AssetId", assetId);
                command.Parameters.AddWithValue("@Ports", portsDisplay ?? (object)DBNull.Value);

                await command.ExecuteNonQueryAsync();
                Logger.Info($"Updated Ports column for asset {assetId} ({hostIp}): {portsDisplay ?? "None"}");
            }
            catch (Exception ex)
            {
                Logger.Error(ex, $"Failed to update Ports column for asset {assetId}");

            }
        }

        public async Task<long> SaveAssetAsync(AssetEntry asset)
        {
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();

                await EnsureMigrationsAsync(connection);

                // Per-unsubmitted uniqueness: a host probed twice in the
                // unsubmitted bucket should overwrite, not duplicate. Once
                // submitted, the row's EngagementId is set and a new probe
                // creates a fresh unsubmitted row.
                var existingAssetId = await GetUnsubmittedAssetIdByHostIpAsync(asset.HostIp);

                if (existingAssetId.HasValue)
                {
                    var updateCommand = connection.CreateCommand();
                    updateCommand.CommandText = @"
                        UPDATE Assets
                        SET HostName = @HostName, MacAddress = @MacAddress, Vendor = @Vendor,
                            IsOnline = @IsOnline, PingTime = @PingTime, ScanTime = @ScanTime,
                            Ports = @Ports,
                            IndustrialVendor = @IndustrialVendor,
                            IndustrialCategory = @IndustrialCategory,
                            IndustrialProtocols = @IndustrialProtocols
                        WHERE Id = @Id
                    ";

                    updateCommand.Parameters.AddWithValue("@Id", existingAssetId.Value);
                    updateCommand.Parameters.AddWithValue("@HostName", asset.HostName ?? (object)DBNull.Value);
                    updateCommand.Parameters.AddWithValue("@MacAddress", asset.MacAddress ?? (object)DBNull.Value);
                    updateCommand.Parameters.AddWithValue("@Vendor", asset.Vendor ?? (object)DBNull.Value);
                    updateCommand.Parameters.AddWithValue("@IsOnline", asset.IsOnline ? 1 : 0);
                    updateCommand.Parameters.AddWithValue("@PingTime", asset.PingTime ?? (object)DBNull.Value);
                    updateCommand.Parameters.AddWithValue("@ScanTime", asset.ScanTime.ToString("O"));
                    updateCommand.Parameters.AddWithValue("@Ports", asset.Ports ?? (object)DBNull.Value);
                    updateCommand.Parameters.AddWithValue("@IndustrialVendor", asset.IndustrialVendor ?? (object)DBNull.Value);
                    updateCommand.Parameters.AddWithValue("@IndustrialCategory", asset.IndustrialCategory ?? (object)DBNull.Value);
                    updateCommand.Parameters.AddWithValue("@IndustrialProtocols", asset.IndustrialProtocols ?? (object)DBNull.Value);

                    await updateCommand.ExecuteNonQueryAsync();
                    return existingAssetId.Value;
                }
                else
                {
                    var command = connection.CreateCommand();
                    command.CommandText = @"
                        INSERT INTO Assets
                        (EngagementId, HostIp, HostName, MacAddress, Vendor, IsOnline, PingTime, ScanTime, CreatedAt,
                         HardwareId, MachineName, Username, UserId, Ports,
                         IndustrialVendor, IndustrialCategory, IndustrialProtocols)
                        VALUES
                        (NULL, @HostIp, @HostName, @MacAddress, @Vendor, @IsOnline, @PingTime, @ScanTime, @CreatedAt,
                         @HardwareId, @MachineName, @Username, @UserId, @Ports,
                         @IndustrialVendor, @IndustrialCategory, @IndustrialProtocols);
                        SELECT last_insert_rowid();
                    ";

                    command.Parameters.AddWithValue("@HostIp", asset.HostIp);
                    command.Parameters.AddWithValue("@HostName", asset.HostName ?? (object)DBNull.Value);
                    command.Parameters.AddWithValue("@MacAddress", asset.MacAddress ?? (object)DBNull.Value);
                    command.Parameters.AddWithValue("@Vendor", asset.Vendor ?? (object)DBNull.Value);
                    command.Parameters.AddWithValue("@IsOnline", asset.IsOnline ? 1 : 0);
                    command.Parameters.AddWithValue("@PingTime", asset.PingTime ?? (object)DBNull.Value);
                    command.Parameters.AddWithValue("@ScanTime", asset.ScanTime.ToString("O"));
                    command.Parameters.AddWithValue("@CreatedAt", asset.CreatedAt.ToString("O"));
                    command.Parameters.AddWithValue("@HardwareId", asset.HardwareId ?? (object)DBNull.Value);
                    command.Parameters.AddWithValue("@MachineName", asset.MachineName ?? (object)DBNull.Value);
                    command.Parameters.AddWithValue("@Username", asset.Username ?? (object)DBNull.Value);
                    command.Parameters.AddWithValue("@UserId", asset.UserId?.ToString() ?? (object)DBNull.Value);
                    command.Parameters.AddWithValue("@Ports", asset.Ports ?? (object)DBNull.Value);
                    command.Parameters.AddWithValue("@IndustrialVendor", asset.IndustrialVendor ?? (object)DBNull.Value);
                    command.Parameters.AddWithValue("@IndustrialCategory", asset.IndustrialCategory ?? (object)DBNull.Value);
                    command.Parameters.AddWithValue("@IndustrialProtocols", asset.IndustrialProtocols ?? (object)DBNull.Value);

                    var result = await command.ExecuteScalarAsync();
                    return Convert.ToInt64(result);
                }
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "Failed to save asset");
                throw;
            }
        }

        private async Task<long?> GetUnsubmittedAssetIdByHostIpAsync(string hostIp)
        {
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();

                var command = connection.CreateCommand();
                command.CommandText = "SELECT Id FROM Assets WHERE HostIp = @HostIp AND EngagementId IS NULL LIMIT 1";
                command.Parameters.AddWithValue("@HostIp", hostIp);

                var result = await command.ExecuteScalarAsync();
                return result != null && result != DBNull.Value ? Convert.ToInt64(result) : (long?)null;
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "Failed to look up unsubmitted asset id by host");
                return null;
            }
        }

        public async Task SavePortAsync(PortEntry port)
        {
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();

                // Per-unsubmitted uniqueness on (host, port, protocol).
                var checkCommand = connection.CreateCommand();
                checkCommand.CommandText = @"
                    SELECT Id FROM Ports
                    WHERE EngagementId IS NULL AND HostIp = @HostIp
                          AND Port = @Port AND Protocol = @Protocol
                    LIMIT 1
                ";
                checkCommand.Parameters.AddWithValue("@HostIp", port.HostIp);
                checkCommand.Parameters.AddWithValue("@Port", port.Port);
                checkCommand.Parameters.AddWithValue("@Protocol", port.Protocol);

                var existingPortId = await checkCommand.ExecuteScalarAsync();

                if (existingPortId != null && existingPortId != DBNull.Value)
                {
                    var updateCommand = connection.CreateCommand();
                    updateCommand.CommandText = @"
                        UPDATE Ports
                        SET Service = @Service, Banner = @Banner, ScanTime = @ScanTime
                        WHERE Id = @Id
                    ";
                    updateCommand.Parameters.AddWithValue("@Id", Convert.ToInt64(existingPortId));
                    updateCommand.Parameters.AddWithValue("@Service", port.Service ?? (object)DBNull.Value);

                    var bannerValue = string.IsNullOrWhiteSpace(port.Banner) ? (object)DBNull.Value : port.Banner.Trim();
                    updateCommand.Parameters.AddWithValue("@Banner", bannerValue);
                    updateCommand.Parameters.AddWithValue("@ScanTime", port.ScanTime.ToString("O"));

                    await updateCommand.ExecuteNonQueryAsync();
                }
                else
                {
                    var command = connection.CreateCommand();
                    command.CommandText = @"
                        INSERT INTO Ports
                        (EngagementId, AssetId, HostIp, Port, Protocol, Service, Banner, ScanTime, CreatedAt,
                         HardwareId, MachineName, Username, UserId)
                        VALUES
                        (NULL, @AssetId, @HostIp, @Port, @Protocol, @Service, @Banner, @ScanTime, @CreatedAt,
                         @HardwareId, @MachineName, @Username, @UserId);
                    ";

                    command.Parameters.AddWithValue("@AssetId", port.AssetId > 0 ? (object)port.AssetId : DBNull.Value);
                    command.Parameters.AddWithValue("@HostIp", port.HostIp);
                    command.Parameters.AddWithValue("@Port", port.Port);
                    command.Parameters.AddWithValue("@Protocol", port.Protocol);
                    command.Parameters.AddWithValue("@Service", port.Service ?? (object)DBNull.Value);

                    var bannerValue = string.IsNullOrWhiteSpace(port.Banner) ? (object)DBNull.Value : port.Banner.Trim();
                    command.Parameters.AddWithValue("@Banner", bannerValue);
                    command.Parameters.AddWithValue("@ScanTime", port.ScanTime.ToString("O"));
                    command.Parameters.AddWithValue("@CreatedAt", port.CreatedAt.ToString("O"));
                    command.Parameters.AddWithValue("@HardwareId", port.HardwareId ?? (object)DBNull.Value);
                    command.Parameters.AddWithValue("@MachineName", port.MachineName ?? (object)DBNull.Value);
                    command.Parameters.AddWithValue("@Username", port.Username ?? (object)DBNull.Value);
                    command.Parameters.AddWithValue("@UserId", port.UserId?.ToString() ?? (object)DBNull.Value);

                    await command.ExecuteNonQueryAsync();
                }

                if (port.AssetId > 0)
                {
                    await UpdateAssetPortsColumnAsync(port.AssetId, port.HostIp);
                }
                else if (!string.IsNullOrEmpty(port.HostIp))
                {
                    var assetId = await GetUnsubmittedAssetIdByHostIpAsync(port.HostIp);
                    if (assetId.HasValue)
                        await UpdateAssetPortsColumnAsync(assetId.Value, port.HostIp);
                }
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "Failed to save port");
                throw;
            }
        }

        public async Task<List<PortEntry>> GetPortsByHostIpAsync(string hostIp)
        {
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();

                var command = connection.CreateCommand();
                command.CommandText = @"
                    SELECT Id, EngagementId, AssetId, HostIp, Port, Protocol, Service, Banner,
                           ScanTime, CreatedAt, HardwareId, MachineName, Username, UserId
                    FROM Ports
                    WHERE HostIp = @HostIp
                    ORDER BY Port ASC
                ";
                command.Parameters.AddWithValue("@HostIp", hostIp);

                var ports = new List<PortEntry>();
                using var portsReader = await command.ExecuteReaderAsync();
                while (await portsReader.ReadAsync())
                {
                    ports.Add(new PortEntry
                    {
                        Id = portsReader.GetInt64(0),
                        EngagementId = portsReader.GetInt32(1),
                        AssetId = portsReader.IsDBNull(2) ? 0 : portsReader.GetInt64(2),
                        HostIp = portsReader.GetString(3),
                        Port = portsReader.GetInt32(4),
                        Protocol = portsReader.GetString(5),
                        Service = portsReader.IsDBNull(6) ? null : portsReader.GetString(6),
                        Banner = portsReader.IsDBNull(7) ? null : portsReader.GetString(7),
                        ScanTime = DateTime.Parse(portsReader.GetString(8)),
                        CreatedAt = DateTime.Parse(portsReader.GetString(9)),
                        HardwareId = portsReader.IsDBNull(10) ? null : portsReader.GetString(10),
                        MachineName = portsReader.IsDBNull(11) ? null : portsReader.GetString(11),
                        Username = portsReader.IsDBNull(12) ? null : portsReader.GetString(12),
                        UserId = portsReader.IsDBNull(13) ? null
                            : (Guid.TryParse(portsReader.GetString(13), out var userId) ? userId : (Guid?)null)
                    });
                }
                return ports;
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "Failed to get ports by host IP");
                throw;
            }
        }

        // Removed in 2.6.0 — engagement-bundled submit obsoletes per-row Synced flag.
        private async Task<List<PortEntry>> GetUnsyncedPortsByHostIpAsync_REMOVED(string hostIp)
        {
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();

                await EnsureMigrationsAsync(connection);

                bool hasHardwareId = false;
                try
                {
                    var checkCommand = connection.CreateCommand();
                    checkCommand.CommandText = "PRAGMA table_info(Ports)";
                    using (var checkReader = await checkCommand.ExecuteReaderAsync())
                    {
                        while (await checkReader.ReadAsync())
                        {
                            if (checkReader.GetString(1) == "HardwareId")
                            {
                                hasHardwareId = true;
                                break;
                            }
                        }
                    }
                }
                catch
                {
                    hasHardwareId = false;
                }

                var command = connection.CreateCommand();
                string query;
                if (hasHardwareId)
                {
                    query = @"
                        SELECT Id, AssetId, HostIp, Port, Protocol, Service, Banner, ScanTime, ProjectName,
                               CreatedAt, Synced, HardwareId, MachineName, Username, UserId
                        FROM Ports
                        WHERE HostIp = @HostIp AND Synced = 0
                        ORDER BY Port ASC
                    ";
                }
                else
                {
                    query = @"
                        SELECT Id, AssetId, HostIp, Port, Protocol, Service, Banner, ScanTime, ProjectName,
                               CreatedAt, Synced
                        FROM Ports
                        WHERE HostIp = @HostIp AND Synced = 0
                        ORDER BY Port ASC
                    ";
                }
                command.CommandText = query;
                command.Parameters.AddWithValue("@HostIp", hostIp);

                return new List<PortEntry>();
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "Failed to get unsynced ports by host IP");
                throw;
            }
        }

        public async Task MarkPortsAsSyncedAsync(IEnumerable<long> portIds, DateTime syncedAt)
        {
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();

                var idsList = portIds.ToList();
                if (idsList.Count == 0) return;

                var checkColumn = connection.CreateCommand();
                checkColumn.CommandText = "PRAGMA table_info(Ports)";
                var hasSyncedAt = false;
                using (var reader = await checkColumn.ExecuteReaderAsync())
                {
                    while (await reader.ReadAsync())
                    {
                        if (reader.GetString(1) == "SyncedAt")
                        {
                            hasSyncedAt = true;
                            break;
                        }
                    }
                }

                var placeholders = string.Join(",", idsList.Select((_, i) => $"@Id{i}"));
                var command = connection.CreateCommand();

                if (hasSyncedAt)
                {
                    command.CommandText = $@"
                        UPDATE Ports
                        SET Synced = 1, SyncedAt = @SyncedAt
                        WHERE Id IN ({placeholders})
                    ";
                    command.Parameters.AddWithValue("@SyncedAt", syncedAt.ToString("O"));
                }
                else
                {
                    command.CommandText = $@"
                        UPDATE Ports
                        SET Synced = 1
                        WHERE Id IN ({placeholders})
                    ";
                }

                for (int i = 0; i < idsList.Count; i++)
                {
                    command.Parameters.AddWithValue($"@Id{i}", idsList[i]);
                }

                await command.ExecuteNonQueryAsync();
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "Failed to mark ports as synced");
                throw;
            }
        }

        // Removed in 2.6.0 — engagement-bundled submit obsoletes per-row Synced flag.

        public async Task MarkAssetsAsSyncedAsync(IEnumerable<long> ids, DateTime syncedAt)
        {
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();

                var idsList = ids.ToList();
                if (idsList.Count == 0) return;

                var placeholders = string.Join(",", idsList.Select((_, i) => $"@Id{i}"));
                var command = connection.CreateCommand();
                command.CommandText = $@"
                    UPDATE Assets
                    SET Synced = 1, SyncedAt = @SyncedAt
                    WHERE Id IN ({placeholders})
                ";

                command.Parameters.AddWithValue("@SyncedAt", syncedAt.ToString("O"));
                for (int i = 0; i < idsList.Count; i++)
                {
                    command.Parameters.AddWithValue($"@Id{i}", idsList[i]);
                }

                await command.ExecuteNonQueryAsync();
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "Failed to mark assets as synced");
                throw;
            }
        }

        public async Task UpdateAssetVendorAndHostnameAsync(long assetId, string? vendor, string? hostname)
        {
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();

                var command = connection.CreateCommand();
                command.CommandText = @"
                    UPDATE Assets
                    SET Vendor = @Vendor, HostName = @HostName
                    WHERE Id = @Id
                ";

                command.Parameters.AddWithValue("@Id", assetId);
                command.Parameters.AddWithValue("@Vendor", vendor ?? (object)DBNull.Value);
                command.Parameters.AddWithValue("@HostName", hostname ?? (object)DBNull.Value);

                await command.ExecuteNonQueryAsync();
            }
            catch (Exception ex)
            {
                Logger.Error(ex, $"Failed to update asset {assetId} vendor/hostname");
                throw;
            }
        }

        public async Task DeleteAssetsAsync(IEnumerable<long> ids)
        {
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();

                var idsList = ids.ToList();
                if (idsList.Count == 0) return;

                var placeholders = string.Join(",", idsList.Select((_, i) => $"@Id{i}"));
                var command = connection.CreateCommand();
                command.CommandText = $@"
                    DELETE FROM Assets
                    WHERE Id IN ({placeholders})
                ";

                for (int i = 0; i < idsList.Count; i++)
                {
                    command.Parameters.AddWithValue($"@Id{i}", idsList[i]);
                }

                await command.ExecuteNonQueryAsync();
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "Failed to delete assets");
                throw;
            }
        }

        public async Task<int> GetUnsyncedAssetsCountAsync()
        {
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();

                var command = connection.CreateCommand();
                command.CommandText = "SELECT COUNT(*) FROM Assets WHERE Synced = 0";

                var result = await command.ExecuteScalarAsync();
                return Convert.ToInt32(result);
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "Failed to get unsynced assets count");
                return 0;
            }
        }

        // Removed in 2.6.0: MapReaderToAsset (legacy SyncWindow shape).

        public async Task<long> SaveReachabilityRunAsync(Models.ReachabilityRun run)
        {
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();

                var command = connection.CreateCommand();
                command.CommandText = @"
                    INSERT INTO reachability_runs
                    (started_at, completed_at, label, source_ip, source_nic, target_raw, results_json,
                     hosts_tested, hosts_reachable, hosts_partial, hosts_unreachable, hosts_no_route)
                    VALUES
                    (@started_at, @completed_at, @label, @source_ip, @source_nic, @target_raw, @results_json,
                     @hosts_tested, @hosts_reachable, @hosts_partial, @hosts_unreachable, @hosts_no_route);
                    SELECT last_insert_rowid();
                ";
                command.Parameters.AddWithValue("@started_at", run.StartedAt.ToString("O"));
                command.Parameters.AddWithValue("@completed_at", run.CompletedAt?.ToString("O") ?? (object)DBNull.Value);
                command.Parameters.AddWithValue("@label", (object?)run.Label ?? DBNull.Value);
                command.Parameters.AddWithValue("@source_ip", (object?)run.SourceIp ?? DBNull.Value);
                command.Parameters.AddWithValue("@source_nic", (object?)run.SourceNic ?? DBNull.Value);
                command.Parameters.AddWithValue("@target_raw", (object?)run.TargetRaw ?? DBNull.Value);
                command.Parameters.AddWithValue("@results_json", (object?)run.ResultsJson ?? DBNull.Value);
                command.Parameters.AddWithValue("@hosts_tested", run.HostsTested);
                command.Parameters.AddWithValue("@hosts_reachable", run.HostsReachable);
                command.Parameters.AddWithValue("@hosts_partial", run.HostsPartial);
                command.Parameters.AddWithValue("@hosts_unreachable", run.HostsUnreachable);
                command.Parameters.AddWithValue("@hosts_no_route", run.HostsNoRoute);

                var id = Convert.ToInt64(await command.ExecuteScalarAsync());
                run.Id = id;
                return id;
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "Failed to save reachability run");
                throw;
            }
        }

        public async Task UpdateReachabilityRunAsync(Models.ReachabilityRun run)
        {
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();

                var command = connection.CreateCommand();
                command.CommandText = @"
                    UPDATE reachability_runs
                    SET started_at = @started_at,
                        completed_at = @completed_at,
                        label = @label,
                        source_ip = @source_ip,
                        source_nic = @source_nic,
                        target_raw = @target_raw,
                        results_json = @results_json,
                        hosts_tested = @hosts_tested,
                        hosts_reachable = @hosts_reachable,
                        hosts_partial = @hosts_partial,
                        hosts_unreachable = @hosts_unreachable,
                        hosts_no_route = @hosts_no_route
                    WHERE id = @id
                ";
                command.Parameters.AddWithValue("@id", run.Id);
                command.Parameters.AddWithValue("@started_at", run.StartedAt.ToString("O"));
                command.Parameters.AddWithValue("@completed_at", run.CompletedAt?.ToString("O") ?? (object)DBNull.Value);
                command.Parameters.AddWithValue("@label", (object?)run.Label ?? DBNull.Value);
                command.Parameters.AddWithValue("@source_ip", (object?)run.SourceIp ?? DBNull.Value);
                command.Parameters.AddWithValue("@source_nic", (object?)run.SourceNic ?? DBNull.Value);
                command.Parameters.AddWithValue("@target_raw", (object?)run.TargetRaw ?? DBNull.Value);
                command.Parameters.AddWithValue("@results_json", (object?)run.ResultsJson ?? DBNull.Value);
                command.Parameters.AddWithValue("@hosts_tested", run.HostsTested);
                command.Parameters.AddWithValue("@hosts_reachable", run.HostsReachable);
                command.Parameters.AddWithValue("@hosts_partial", run.HostsPartial);
                command.Parameters.AddWithValue("@hosts_unreachable", run.HostsUnreachable);
                command.Parameters.AddWithValue("@hosts_no_route", run.HostsNoRoute);

                await command.ExecuteNonQueryAsync();
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "Failed to update reachability run");
                throw;
            }
        }

        public async Task<List<Models.ReachabilityRun>> GetReachabilityRunsAsync(int? limit = null)
        {
            var runs = new List<Models.ReachabilityRun>();
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();

                var command = connection.CreateCommand();
                command.CommandText = @"
                    SELECT id, started_at, completed_at, label, source_ip, source_nic, target_raw, results_json,
                           hosts_tested, hosts_reachable, hosts_partial, hosts_unreachable, hosts_no_route
                    FROM reachability_runs
                    ORDER BY started_at DESC
                " + (limit.HasValue ? " LIMIT @limit" : string.Empty);
                if (limit.HasValue)
                {
                    command.Parameters.AddWithValue("@limit", limit.Value);
                }

                using var reader = await command.ExecuteReaderAsync();
                while (await reader.ReadAsync())
                {
                    runs.Add(MapReaderToRun(reader));
                }
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "Failed to get reachability runs");
            }
            return runs;
        }

        public async Task<Models.ReachabilityRun?> GetReachabilityRunAsync(long id)
        {
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();

                var command = connection.CreateCommand();
                command.CommandText = @"
                    SELECT id, started_at, completed_at, label, source_ip, source_nic, target_raw, results_json,
                           hosts_tested, hosts_reachable, hosts_partial, hosts_unreachable, hosts_no_route
                    FROM reachability_runs
                    WHERE id = @id
                ";
                command.Parameters.AddWithValue("@id", id);

                using var reader = await command.ExecuteReaderAsync();
                if (await reader.ReadAsync())
                {
                    return MapReaderToRun(reader);
                }
            }
            catch (Exception ex)
            {
                Logger.Error(ex, $"Failed to get reachability run {id}");
            }
            return null;
        }

        public async Task DeleteReachabilityRunAsync(long id)
        {
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();

                var command = connection.CreateCommand();
                command.CommandText = "DELETE FROM reachability_runs WHERE id = @id";
                command.Parameters.AddWithValue("@id", id);
                await command.ExecuteNonQueryAsync();
            }
            catch (Exception ex)
            {
                Logger.Error(ex, $"Failed to delete reachability run {id}");
                throw;
            }
        }

        private static Models.ReachabilityRun MapReaderToRun(DbDataReader reader)
        {
            return new Models.ReachabilityRun
            {
                Id = reader.GetInt64(0),
                StartedAt = DateTime.Parse(reader.GetString(1)),
                CompletedAt = reader.IsDBNull(2) ? null : DateTime.Parse(reader.GetString(2)),
                Label = reader.IsDBNull(3) ? null : reader.GetString(3),
                SourceIp = reader.IsDBNull(4) ? null : reader.GetString(4),
                SourceNic = reader.IsDBNull(5) ? null : reader.GetString(5),
                TargetRaw = reader.IsDBNull(6) ? null : reader.GetString(6),
                ResultsJson = reader.IsDBNull(7) ? null : reader.GetString(7),
                HostsTested = reader.IsDBNull(8) ? 0 : reader.GetInt32(8),
                HostsReachable = reader.IsDBNull(9) ? 0 : reader.GetInt32(9),
                HostsPartial = reader.IsDBNull(10) ? 0 : reader.GetInt32(10),
                HostsUnreachable = reader.IsDBNull(11) ? 0 : reader.GetInt32(11),
                HostsNoRoute = reader.IsDBNull(12) ? 0 : reader.GetInt32(12)
            };
        }

        // Removed in 2.6.0: MapReaderToEntry (legacy SyncWindow shape — replaced by GetAttackLogsForEngagementAsync).

        // ─── Engagement repository ─────────────────────────────────────

        public async Task<int> InsertEngagementAsync(Engagement engagement)
        {
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();

                var command = connection.CreateCommand();
                command.CommandText = @"
                    INSERT INTO Engagements
                    (RemoteId, Name, ClientName, Scope, StartedAt, EndedAt, Status,
                     SurveyorHardwareId, SurveyorEmail, Notes, CreatedAt, SubmittedAt)
                    VALUES
                    (@RemoteId, @Name, @ClientName, @Scope, @StartedAt, @EndedAt, @Status,
                     @SurveyorHardwareId, @SurveyorEmail, @Notes, @CreatedAt, @SubmittedAt);
                    SELECT last_insert_rowid();
                ";

                command.Parameters.AddWithValue("@RemoteId", engagement.RemoteId ?? (object)DBNull.Value);
                command.Parameters.AddWithValue("@Name", engagement.Name);
                command.Parameters.AddWithValue("@ClientName", engagement.ClientName ?? (object)DBNull.Value);
                command.Parameters.AddWithValue("@Scope", engagement.Scope ?? (object)DBNull.Value);
                command.Parameters.AddWithValue("@StartedAt", engagement.StartedAt.ToString("O"));
                command.Parameters.AddWithValue("@EndedAt", engagement.EndedAt.HasValue ? engagement.EndedAt.Value.ToString("O") : (object)DBNull.Value);
                command.Parameters.AddWithValue("@Status", engagement.Status.ToString());
                command.Parameters.AddWithValue("@SurveyorHardwareId", engagement.SurveyorHardwareId);
                command.Parameters.AddWithValue("@SurveyorEmail", engagement.SurveyorEmail ?? (object)DBNull.Value);
                command.Parameters.AddWithValue("@Notes", engagement.Notes ?? (object)DBNull.Value);
                command.Parameters.AddWithValue("@CreatedAt", engagement.CreatedAt.ToString("O"));
                command.Parameters.AddWithValue("@SubmittedAt", engagement.SubmittedAt.HasValue ? engagement.SubmittedAt.Value.ToString("O") : (object)DBNull.Value);

                var result = await command.ExecuteScalarAsync();
                engagement.Id = Convert.ToInt32(result);
                return engagement.Id;
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "Failed to insert engagement");
                throw;
            }
        }

        /// <summary>
        /// On successful submit, tag every unsubmitted row with the new
        /// EngagementId so it disappears from the "to submit" bucket but
        /// stays on disk as a record of what was submitted.
        /// </summary>
        public async Task<int> AssignEngagementIdToUnsubmittedAsync(int engagementId)
        {
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();

                int total = 0;
                foreach (var sql in new[]
                {
                    "UPDATE Assets        SET EngagementId = @e WHERE EngagementId IS NULL",
                    "UPDATE Ports         SET EngagementId = @e WHERE EngagementId IS NULL",
                    "UPDATE AttackLogs    SET EngagementId = @e WHERE EngagementId IS NULL",
                    "UPDATE reachability_runs SET EngagementId = @e WHERE EngagementId IS NULL",
                    "UPDATE TopologyNodes  SET EngagementId = @e WHERE EngagementId IS NULL",
                    "UPDATE TopologyEdges  SET EngagementId = @e WHERE EngagementId IS NULL",
                    "UPDATE TopologySubnets SET EngagementId = @e WHERE EngagementId IS NULL",
                    "UPDATE TraceroutePaths SET EngagementId = @e WHERE EngagementId IS NULL"
                })
                {
                    var cmd = connection.CreateCommand();
                    cmd.CommandText = sql;
                    cmd.Parameters.AddWithValue("@e", engagementId);
                    total += await cmd.ExecuteNonQueryAsync();
                }
                return total;
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "Failed to assign engagement id to unsubmitted rows");
                throw;
            }
        }

        /// <summary>
        /// On successful submit when the user chose "clear after submit": hard
        /// delete every row that was just packaged into the engagement. Engagements
        /// metadata table is NOT touched — that's our ledger of past submissions.
        /// </summary>
        public async Task<int> DeleteAllUnsubmittedAsync()
        {
            return await DeleteScanRowsAsync(onlyUnsubmitted: true).ConfigureAwait(false);
        }

        /// <summary>
        /// Settings → "Clear all local scan data". Wipes all scan/topology rows
        /// regardless of submit status. Engagements metadata preserved.
        /// </summary>
        public async Task<int> DeleteAllScanDataAsync()
        {
            return await DeleteScanRowsAsync(onlyUnsubmitted: false).ConfigureAwait(false);
        }

        private async Task<int> DeleteScanRowsAsync(bool onlyUnsubmitted)
        {
            var where = onlyUnsubmitted ? "WHERE EngagementId IS NULL" : "";
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();

                int total = 0;
                foreach (var table in new[]
                {
                    "Ports", "Assets", "AttackLogs", "reachability_runs",
                    "TopologyNodes", "TopologyEdges", "TopologySubnets", "TraceroutePaths"
                })
                {
                    var cmd = connection.CreateCommand();
                    cmd.CommandText = $"DELETE FROM {table} {where}";
                    total += await cmd.ExecuteNonQueryAsync();
                }
                return total;
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "Failed to delete scan rows");
                throw;
            }
        }

        // ─── Topology persistence ─────────────────────────────────────

        public sealed class TopologyNodeRow
        {
            public string NodeId { get; set; } = string.Empty;
            public string NodeType { get; set; } = string.Empty;
            public string? Ip { get; set; }
            public string? Mac { get; set; }
            public string? Vendor { get; set; }
            public string? Hostname { get; set; }
            public string? AttributesJson { get; set; }
        }

        public sealed class TopologyEdgeRow
        {
            public string SourceNodeId { get; set; } = string.Empty;
            public string TargetNodeId { get; set; } = string.Empty;
            public string EdgeType { get; set; } = string.Empty;
            public string? AttributesJson { get; set; }
        }

        public sealed class TopologySubnetRow
        {
            public string SubnetCidr { get; set; } = string.Empty;
            public string? Network { get; set; }
            public bool IsLocal { get; set; }
            public bool IsInternet { get; set; }
        }

        /// <summary>
        /// Upsert in-memory topology snapshot into the unsubmitted bucket.
        /// Called from a 1s-debounced background timer in DiscoveryOrchestrator
        /// so rapid discovery doesn't spam DB writes.
        /// </summary>
        public async Task UpsertTopologyAsync(
            IEnumerable<TopologyNodeRow> nodes,
            IEnumerable<TopologyEdgeRow> edges,
            IEnumerable<TopologySubnetRow> subnets)
        {
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();
                using var tx = (SqliteTransaction)await connection.BeginTransactionAsync();

                var now = DateTime.UtcNow.ToString("O");

                foreach (var n in nodes)
                {
                    var cmd = connection.CreateCommand();
                    cmd.Transaction = tx;
                    cmd.CommandText = @"
                        INSERT INTO TopologyNodes
                            (NodeId, NodeType, Ip, Mac, Vendor, Hostname, Attributes,
                             EngagementId, DiscoveredAt, LastUpdatedAt)
                        VALUES
                            (@NodeId, @NodeType, @Ip, @Mac, @Vendor, @Hostname, @Attributes,
                             NULL, @Now, @Now)
                        ON CONFLICT(NodeId) WHERE EngagementId IS NULL DO UPDATE SET
                            NodeType = excluded.NodeType,
                            Ip = COALESCE(excluded.Ip, TopologyNodes.Ip),
                            Mac = COALESCE(excluded.Mac, TopologyNodes.Mac),
                            Vendor = COALESCE(excluded.Vendor, TopologyNodes.Vendor),
                            Hostname = COALESCE(excluded.Hostname, TopologyNodes.Hostname),
                            Attributes = excluded.Attributes,
                            LastUpdatedAt = @Now
                    ";
                    cmd.Parameters.AddWithValue("@NodeId", n.NodeId);
                    cmd.Parameters.AddWithValue("@NodeType", n.NodeType);
                    cmd.Parameters.AddWithValue("@Ip", (object?)n.Ip ?? DBNull.Value);
                    cmd.Parameters.AddWithValue("@Mac", (object?)n.Mac ?? DBNull.Value);
                    cmd.Parameters.AddWithValue("@Vendor", (object?)n.Vendor ?? DBNull.Value);
                    cmd.Parameters.AddWithValue("@Hostname", (object?)n.Hostname ?? DBNull.Value);
                    cmd.Parameters.AddWithValue("@Attributes", (object?)n.AttributesJson ?? DBNull.Value);
                    cmd.Parameters.AddWithValue("@Now", now);
                    await cmd.ExecuteNonQueryAsync();
                }

                foreach (var e in edges)
                {
                    var cmd = connection.CreateCommand();
                    cmd.Transaction = tx;
                    cmd.CommandText = @"
                        INSERT INTO TopologyEdges
                            (SourceNodeId, TargetNodeId, EdgeType, Attributes,
                             EngagementId, DiscoveredAt)
                        VALUES (@S, @T, @Type, @Attr, NULL, @Now)
                        ON CONFLICT(SourceNodeId, TargetNodeId, EdgeType) WHERE EngagementId IS NULL DO UPDATE SET
                            Attributes = excluded.Attributes
                    ";
                    cmd.Parameters.AddWithValue("@S", e.SourceNodeId);
                    cmd.Parameters.AddWithValue("@T", e.TargetNodeId);
                    cmd.Parameters.AddWithValue("@Type", e.EdgeType);
                    cmd.Parameters.AddWithValue("@Attr", (object?)e.AttributesJson ?? DBNull.Value);
                    cmd.Parameters.AddWithValue("@Now", now);
                    await cmd.ExecuteNonQueryAsync();
                }

                foreach (var s in subnets)
                {
                    var cmd = connection.CreateCommand();
                    cmd.Transaction = tx;
                    cmd.CommandText = @"
                        INSERT INTO TopologySubnets
                            (SubnetCidr, Network, IsLocal, IsInternet, EngagementId, DiscoveredAt)
                        SELECT @Cidr, @Network, @IsLocal, @IsInternet, NULL, @Now
                        WHERE NOT EXISTS (
                            SELECT 1 FROM TopologySubnets
                            WHERE SubnetCidr = @Cidr AND EngagementId IS NULL
                        )
                    ";
                    cmd.Parameters.AddWithValue("@Cidr", s.SubnetCidr);
                    cmd.Parameters.AddWithValue("@Network", (object?)s.Network ?? DBNull.Value);
                    cmd.Parameters.AddWithValue("@IsLocal", s.IsLocal ? 1 : 0);
                    cmd.Parameters.AddWithValue("@IsInternet", s.IsInternet ? 1 : 0);
                    cmd.Parameters.AddWithValue("@Now", now);
                    await cmd.ExecuteNonQueryAsync();
                }

                await tx.CommitAsync();
            }
            catch (Exception ex)
            {
                Logger.Warn(ex, "[DB] UpsertTopologyAsync failed (non-fatal)");
            }
        }

        /// <summary>
        /// Reload unsubmitted topology rows on launch so the canvas renders
        /// without waiting for fresh discovery.
        /// </summary>
        public async Task<(List<TopologyNodeRow> Nodes, List<TopologyEdgeRow> Edges, List<TopologySubnetRow> Subnets)>
            LoadUnsubmittedTopologyAsync()
        {
            var nodes = new List<TopologyNodeRow>();
            var edges = new List<TopologyEdgeRow>();
            var subnets = new List<TopologySubnetRow>();
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();

                var nodeCmd = connection.CreateCommand();
                nodeCmd.CommandText = @"
                    SELECT NodeId, NodeType, Ip, Mac, Vendor, Hostname, Attributes
                    FROM TopologyNodes WHERE EngagementId IS NULL
                ";
                using (var rdr = await nodeCmd.ExecuteReaderAsync())
                {
                    while (await rdr.ReadAsync())
                    {
                        nodes.Add(new TopologyNodeRow
                        {
                            NodeId = rdr.GetString(0),
                            NodeType = rdr.GetString(1),
                            Ip = rdr.IsDBNull(2) ? null : rdr.GetString(2),
                            Mac = rdr.IsDBNull(3) ? null : rdr.GetString(3),
                            Vendor = rdr.IsDBNull(4) ? null : rdr.GetString(4),
                            Hostname = rdr.IsDBNull(5) ? null : rdr.GetString(5),
                            AttributesJson = rdr.IsDBNull(6) ? null : rdr.GetString(6)
                        });
                    }
                }

                var edgeCmd = connection.CreateCommand();
                edgeCmd.CommandText = @"
                    SELECT SourceNodeId, TargetNodeId, EdgeType, Attributes
                    FROM TopologyEdges WHERE EngagementId IS NULL
                ";
                using (var rdr = await edgeCmd.ExecuteReaderAsync())
                {
                    while (await rdr.ReadAsync())
                    {
                        edges.Add(new TopologyEdgeRow
                        {
                            SourceNodeId = rdr.GetString(0),
                            TargetNodeId = rdr.GetString(1),
                            EdgeType = rdr.GetString(2),
                            AttributesJson = rdr.IsDBNull(3) ? null : rdr.GetString(3)
                        });
                    }
                }

                var subnetCmd = connection.CreateCommand();
                subnetCmd.CommandText = @"
                    SELECT SubnetCidr, Network, IsLocal, IsInternet
                    FROM TopologySubnets WHERE EngagementId IS NULL
                ";
                using (var rdr = await subnetCmd.ExecuteReaderAsync())
                {
                    while (await rdr.ReadAsync())
                    {
                        subnets.Add(new TopologySubnetRow
                        {
                            SubnetCidr = rdr.GetString(0),
                            Network = rdr.IsDBNull(1) ? null : rdr.GetString(1),
                            IsLocal = rdr.GetInt32(2) == 1,
                            IsInternet = rdr.GetInt32(3) == 1
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.Warn(ex, "[DB] LoadUnsubmittedTopologyAsync failed (non-fatal)");
            }
            return (nodes, edges, subnets);
        }

        public async Task<int> CountUnsubmittedTopologyNodesAsync()
        {
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();
                var cmd = connection.CreateCommand();
                cmd.CommandText = "SELECT COUNT(*) FROM TopologyNodes WHERE EngagementId IS NULL";
                return Convert.ToInt32(await cmd.ExecuteScalarAsync());
            }
            catch { return 0; }
        }

        /// <summary>
        /// Distinct from CountUnsubmittedTopologyNodesAsync: only counts node
        /// rows that represent actual scanned hosts (Host or RemoteHost), not
        /// Self / Gateway / SubnetCloud / UnknownHop. Drives the submit
        /// dialog's "Hosts discovered" line.
        /// </summary>
        public async Task<int> CountUnsubmittedTopologyHostNodesAsync()
        {
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();
                var cmd = connection.CreateCommand();
                cmd.CommandText = @"
                    SELECT COUNT(*) FROM TopologyNodes
                    WHERE EngagementId IS NULL
                      AND NodeType IN ('Host', 'RemoteHost')
                ";
                return Convert.ToInt32(await cmd.ExecuteScalarAsync());
            }
            catch { return 0; }
        }

        public async Task<int> CountUnsubmittedTopologySubnetsAsync()
        {
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();
                var cmd = connection.CreateCommand();
                cmd.CommandText = @"
                    SELECT COUNT(*) FROM TopologySubnets
                    WHERE EngagementId IS NULL
                ";
                return Convert.ToInt32(await cmd.ExecuteScalarAsync());
            }
            catch { return 0; }
        }

        public async Task<int> CountSubmittedEngagementsAsync()
        {
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();
                var cmd = connection.CreateCommand();
                cmd.CommandText = "SELECT COUNT(*) FROM Engagements WHERE Status = 'Submitted'";
                return Convert.ToInt32(await cmd.ExecuteScalarAsync());
            }
            catch { return 0; }
        }

        public async Task UpdateEngagementAsync(Engagement engagement)
        {
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();

                var command = connection.CreateCommand();
                command.CommandText = @"
                    UPDATE Engagements SET
                        RemoteId = @RemoteId,
                        Name = @Name,
                        ClientName = @ClientName,
                        Scope = @Scope,
                        StartedAt = @StartedAt,
                        EndedAt = @EndedAt,
                        Status = @Status,
                        SurveyorHardwareId = @SurveyorHardwareId,
                        SurveyorEmail = @SurveyorEmail,
                        Notes = @Notes,
                        SubmittedAt = @SubmittedAt
                    WHERE Id = @Id
                ";

                command.Parameters.AddWithValue("@Id", engagement.Id);
                command.Parameters.AddWithValue("@RemoteId", engagement.RemoteId ?? (object)DBNull.Value);
                command.Parameters.AddWithValue("@Name", engagement.Name);
                command.Parameters.AddWithValue("@ClientName", engagement.ClientName ?? (object)DBNull.Value);
                command.Parameters.AddWithValue("@Scope", engagement.Scope ?? (object)DBNull.Value);
                command.Parameters.AddWithValue("@StartedAt", engagement.StartedAt.ToString("O"));
                command.Parameters.AddWithValue("@EndedAt", engagement.EndedAt.HasValue ? engagement.EndedAt.Value.ToString("O") : (object)DBNull.Value);
                command.Parameters.AddWithValue("@Status", engagement.Status.ToString());
                command.Parameters.AddWithValue("@SurveyorHardwareId", engagement.SurveyorHardwareId);
                command.Parameters.AddWithValue("@SurveyorEmail", engagement.SurveyorEmail ?? (object)DBNull.Value);
                command.Parameters.AddWithValue("@Notes", engagement.Notes ?? (object)DBNull.Value);
                command.Parameters.AddWithValue("@SubmittedAt", engagement.SubmittedAt.HasValue ? engagement.SubmittedAt.Value.ToString("O") : (object)DBNull.Value);

                await command.ExecuteNonQueryAsync();
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "Failed to update engagement");
                throw;
            }
        }

        public async Task<int> CountUnsubmittedAssetsAsync()
        {
            using var connection = new SqliteConnection(_connectionString);
            await connection.OpenAsync();
            var command = connection.CreateCommand();
            command.CommandText = "SELECT COUNT(*) FROM Assets WHERE EngagementId IS NULL";
            return Convert.ToInt32(await command.ExecuteScalarAsync());
        }

        public async Task<int> CountUnsubmittedAttackLogsAsync()
        {
            using var connection = new SqliteConnection(_connectionString);
            await connection.OpenAsync();
            var command = connection.CreateCommand();
            command.CommandText = "SELECT COUNT(*) FROM AttackLogs WHERE EngagementId IS NULL";
            return Convert.ToInt32(await command.ExecuteScalarAsync());
        }

        /// <summary>
        /// True when ANY scan/probe/attack/topology row is unsubmitted.
        /// Drives the MainWindow Submit-assessment button enable state.
        /// </summary>
        public async Task<bool> HasUnsubmittedActivityAsync()
        {
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();
                var command = connection.CreateCommand();
                command.CommandText = @"
                    SELECT EXISTS(SELECT 1 FROM Assets        WHERE EngagementId IS NULL)
                        OR EXISTS(SELECT 1 FROM AttackLogs    WHERE EngagementId IS NULL)
                        OR EXISTS(SELECT 1 FROM TopologyNodes WHERE EngagementId IS NULL)
                        OR EXISTS(SELECT 1 FROM TopologyEdges WHERE EngagementId IS NULL)
                        OR EXISTS(SELECT 1 FROM TopologySubnets WHERE EngagementId IS NULL)
                        OR EXISTS(SELECT 1 FROM TraceroutePaths WHERE EngagementId IS NULL)
                ";
                var result = await command.ExecuteScalarAsync();
                return Convert.ToInt32(result) == 1;
            }
            catch (Exception ex)
            {
                Logger.Warn(ex, "[DB] HasUnsubmittedActivityAsync failed; reporting false");
                return false;
            }
        }

        /// <summary>
        /// Pre-submit fetch: rows that belong to this session and have not yet
        /// been packaged into an engagement. After submit, AssignEngagementIdAsync
        /// flips EngagementId on these rows so they no longer appear here.
        /// </summary>
        public async Task<List<AssetEntry>> GetUnsubmittedAssetsAsync()
        {
            var assets = new List<AssetEntry>();
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();

                var command = connection.CreateCommand();
                command.CommandText = @"
                    SELECT Id, COALESCE(EngagementId, 0), HostIp, HostName, MacAddress, Vendor, IsOnline, PingTime,
                           ScanTime, CreatedAt, HardwareId, MachineName, Username, UserId, Ports,
                           IndustrialVendor, IndustrialCategory, IndustrialProtocols
                    FROM Assets
                    WHERE EngagementId IS NULL
                    ORDER BY HostIp ASC
                ";

                using var reader = await command.ExecuteReaderAsync();
                while (await reader.ReadAsync())
                {
                    assets.Add(new AssetEntry
                    {
                        Id = reader.GetInt64(0),
                        EngagementId = reader.GetInt32(1),
                        HostIp = reader.GetString(2),
                        HostName = reader.IsDBNull(3) ? null : reader.GetString(3),
                        MacAddress = reader.IsDBNull(4) ? null : reader.GetString(4),
                        Vendor = reader.IsDBNull(5) ? null : reader.GetString(5),
                        IsOnline = reader.GetInt32(6) == 1,
                        PingTime = reader.IsDBNull(7) ? null : (int?)reader.GetInt32(7),
                        ScanTime = DateTime.Parse(reader.GetString(8)),
                        CreatedAt = DateTime.Parse(reader.GetString(9)),
                        HardwareId = reader.IsDBNull(10) ? null : reader.GetString(10),
                        MachineName = reader.IsDBNull(11) ? null : reader.GetString(11),
                        Username = reader.IsDBNull(12) ? null : reader.GetString(12),
                        UserId = reader.IsDBNull(13) ? null
                            : (Guid.TryParse(reader.GetString(13), out var uid) ? uid : (Guid?)null),
                        Ports = reader.IsDBNull(14) ? null : reader.GetString(14),
                        IndustrialVendor = reader.IsDBNull(15) ? null : reader.GetString(15),
                        IndustrialCategory = reader.IsDBNull(16) ? null : reader.GetString(16),
                        IndustrialProtocols = reader.IsDBNull(17) ? null : reader.GetString(17)
                    });
                }
            }
            catch (Exception ex) { Logger.Error(ex, "Failed to load assets for engagement"); }
            return assets;
        }

        public async Task<List<PortEntry>> GetUnsubmittedPortsAsync()
        {
            var ports = new List<PortEntry>();
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();

                var command = connection.CreateCommand();
                command.CommandText = @"
                    SELECT Id, COALESCE(EngagementId, 0), AssetId, HostIp, Port, Protocol, Service, Banner,
                           ScanTime, CreatedAt, HardwareId, MachineName, Username, UserId
                    FROM Ports
                    WHERE EngagementId IS NULL
                    ORDER BY HostIp ASC, Port ASC
                ";

                using var reader = await command.ExecuteReaderAsync();
                while (await reader.ReadAsync())
                {
                    ports.Add(new PortEntry
                    {
                        Id = reader.GetInt64(0),
                        EngagementId = reader.GetInt32(1),
                        AssetId = reader.IsDBNull(2) ? 0 : reader.GetInt64(2),
                        HostIp = reader.GetString(3),
                        Port = reader.GetInt32(4),
                        Protocol = reader.GetString(5),
                        Service = reader.IsDBNull(6) ? null : reader.GetString(6),
                        Banner = reader.IsDBNull(7) ? null : reader.GetString(7),
                        ScanTime = DateTime.Parse(reader.GetString(8)),
                        CreatedAt = DateTime.Parse(reader.GetString(9)),
                        HardwareId = reader.IsDBNull(10) ? null : reader.GetString(10),
                        MachineName = reader.IsDBNull(11) ? null : reader.GetString(11),
                        Username = reader.IsDBNull(12) ? null : reader.GetString(12),
                        UserId = reader.IsDBNull(13) ? null
                            : (Guid.TryParse(reader.GetString(13), out var uid) ? uid : (Guid?)null)
                    });
                }
            }
            catch (Exception ex) { Logger.Error(ex, "Failed to load ports for engagement"); }
            return ports;
        }

        public async Task<List<AttackLogEntry>> GetUnsubmittedAttackLogsAsync()
        {
            var logs = new List<AttackLogEntry>();
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();

                var command = connection.CreateCommand();
                command.CommandText = @"
                    SELECT Id, COALESCE(EngagementId, 0), AttackType, Protocol, SourceIp, SourceMac, TargetIp, TargetMac,
                           TargetPort, TargetRateMbps, PacketsSent, DurationSeconds, StartTime, StopTime,
                           Note, LogContent, CreatedAt, HardwareId, MachineName, Username, UserId
                    FROM AttackLogs
                    WHERE EngagementId IS NULL
                    ORDER BY StartTime ASC
                ";

                using var reader = await command.ExecuteReaderAsync();
                while (await reader.ReadAsync())
                {
                    logs.Add(new AttackLogEntry
                    {
                        Id = reader.GetInt64(0),
                        EngagementId = reader.GetInt32(1),
                        AttackType = reader.GetString(2),
                        Protocol = reader.GetString(3),
                        SourceIp = reader.GetString(4),
                        SourceMac = reader.IsDBNull(5) ? null : reader.GetString(5),
                        TargetIp = reader.GetString(6),
                        TargetMac = reader.IsDBNull(7) ? null : reader.GetString(7),
                        TargetPort = reader.GetInt32(8),
                        TargetRateMbps = reader.GetDouble(9),
                        PacketsSent = reader.GetInt64(10),
                        DurationSeconds = reader.GetInt32(11),
                        StartTime = DateTime.Parse(reader.GetString(12)),
                        StopTime = DateTime.Parse(reader.GetString(13)),
                        Note = reader.IsDBNull(14) ? null : reader.GetString(14),
                        LogContent = reader.GetString(15),
                        CreatedAt = DateTime.Parse(reader.GetString(16)),
                        HardwareId = reader.IsDBNull(17) ? null : reader.GetString(17),
                        MachineName = reader.IsDBNull(18) ? null : reader.GetString(18),
                        Username = reader.IsDBNull(19) ? null : reader.GetString(19),
                        UserId = reader.IsDBNull(20) ? null
                            : (Guid.TryParse(reader.GetString(20), out var uid) ? uid : (Guid?)null)
                    });
                }
            }
            catch (Exception ex) { Logger.Error(ex, "Failed to load attack logs for engagement"); }
            return logs;
        }

        private static Engagement MapReaderToEngagement(DbDataReader reader)
        {
            return new Engagement
            {
                Id = reader.GetInt32(0),
                RemoteId = reader.IsDBNull(1) ? null : reader.GetString(1),
                Name = reader.GetString(2),
                ClientName = reader.IsDBNull(3) ? null : reader.GetString(3),
                Scope = reader.IsDBNull(4) ? null : reader.GetString(4),
                StartedAt = DateTime.Parse(reader.GetString(5)),
                EndedAt = reader.IsDBNull(6) ? null : (DateTime?)DateTime.Parse(reader.GetString(6)),
                Status = Enum.TryParse<EngagementStatus>(reader.GetString(7), out var st) ? st : EngagementStatus.Active,
                SurveyorHardwareId = reader.GetString(8),
                SurveyorEmail = reader.IsDBNull(9) ? null : reader.GetString(9),
                Notes = reader.IsDBNull(10) ? null : reader.GetString(10),
                CreatedAt = DateTime.Parse(reader.GetString(11)),
                SubmittedAt = reader.IsDBNull(12) ? null : (DateTime?)DateTime.Parse(reader.GetString(12))
            };
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (_disposed)
                return;

            if (disposing)
            {

                Logger.Debug("DatabaseService disposed");
            }

            _disposed = true;
        }
    }
}

