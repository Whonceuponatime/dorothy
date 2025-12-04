using System;
using System.Collections.Generic;
using System.Data.Common;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Threading.Tasks;
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
            
            // For version 2.2.7 only: Check if database needs recreation due to missing columns
            CheckAndRecreateDatabaseIfNeeded();
            
            InitializeDatabase();
        }

        /// <summary>
        /// For version 2.2.7 only: Check if database is old (missing HardwareId columns) and recreate it.
        /// This is a one-time migration to fix databases that were created before the migration logic was added.
        /// </summary>
        private void CheckAndRecreateDatabaseIfNeeded()
        {
            try
            {
                // Check current version
                var currentVersion = System.Reflection.Assembly.GetExecutingAssembly().GetName().Version;
                if (currentVersion == null || currentVersion.Major != 2 || currentVersion.Minor != 2 || currentVersion.Build != 7)
                {
                    // Not version 2.2.7, skip recreation
                    Logger.Info($"Skipping database recreation check - not version 2.2.7 (current: {currentVersion?.Major}.{currentVersion?.Minor}.{currentVersion?.Build})");
                    return;
                }

                Logger.Info("Version 2.2.7: Checking database schema for required columns...");

                // Check if database file exists
                if (!File.Exists(_dbPath))
                {
                    // Database doesn't exist, will be created fresh
                    Logger.Info("Database file does not exist - will be created with correct schema.");
                    return;
                }

                // Check if database is old (missing HardwareId columns)
                bool needsRecreation = false;
                SqliteConnection? checkConnection = null;
                try
                {
                    checkConnection = new SqliteConnection(_connectionString);
                    checkConnection.Open();

                    // Check Assets table
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
                        // If we can't check, assume it needs recreation
                        assetsNeedsRecreation = true;
                    }

                    // Check Ports table
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
                        // If we can't check, assume it needs recreation
                        portsNeedsRecreation = true;
                    }

                    // Check AttackLogs table
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
                        // If we can't check, assume it needs recreation
                        attackLogsNeedsRecreation = true;
                    }

                    // If any table is missing HardwareId, mark for recreation
                    needsRecreation = assetsNeedsRecreation || portsNeedsRecreation || attackLogsNeedsRecreation;
                }
                catch (Exception checkEx)
                {
                    Logger.Warn(checkEx, "Error checking database schema - will attempt recreation as safety measure.");
                    needsRecreation = true; // If we can't check, assume it needs recreation
                }
                finally
                {
                    // Always close the connection
                    if (checkConnection != null)
                    {
                        checkConnection.Close();
                        checkConnection.Dispose();
                    }
                }

                // If any table is missing HardwareId, delete and recreate the database
                if (needsRecreation)
                {
                    Logger.Info("Version 2.2.7: Detected old database schema (missing HardwareId columns). Deleting and recreating database...");

                    // Backup old database (optional - for safety)
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

                    // Force garbage collection to release any file handles
                    GC.Collect();
                    GC.WaitForPendingFinalizers();
                    System.Threading.Thread.Sleep(100); // Brief pause to ensure file handles are released

                    // Delete old database - retry if file is locked
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
                                deleted = true; // Already deleted
                            }
                        }
                        catch (Exception deleteEx)
                        {
                            if (i < retries - 1)
                            {
                                Logger.Warn($"Failed to delete database (attempt {i + 1}/{retries}), retrying in 500ms...");
                                System.Threading.Thread.Sleep(500); // Wait 500ms before retry
                            }
                            else
                            {
                                Logger.Error(deleteEx, "Failed to delete old database after multiple attempts. User may need to manually delete the database file.");
                                // Don't throw - allow initialization to proceed, migration will attempt to add columns
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
                // Try to delete the database file anyway as a safety measure
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
        }

        private void MigrateDatabase(SqliteConnection connection)
        {
            try
            {
                // Migrate ReachabilityTests table: Add IsSynced if it doesn't exist
                try
                {
                    var checkReachabilityTable = connection.CreateCommand();
                    checkReachabilityTable.CommandText = @"
                        SELECT name FROM sqlite_master 
                        WHERE type='table' AND name='ReachabilityTests';
                    ";
                    var reachabilityTableExists = checkReachabilityTable.ExecuteScalar() != null;

                    if (reachabilityTableExists)
                    {
                        // Check columns
                        var checkColumns = connection.CreateCommand();
                        checkColumns.CommandText = "PRAGMA table_info(ReachabilityTests)";
                        var columns = new HashSet<string>();
                        using (var reader = checkColumns.ExecuteReader())
                        {
                            while (reader.Read())
                            {
                                columns.Add(reader.GetString(1));
                            }
                        }

                        // If Synced exists but IsSynced doesn't, add IsSynced and copy data
                        if (columns.Contains("Synced") && !columns.Contains("IsSynced"))
                        {
                            var addColumn = connection.CreateCommand();
                            addColumn.CommandText = @"
                                ALTER TABLE ReachabilityTests ADD COLUMN IsSynced INTEGER NOT NULL DEFAULT 0;
                                UPDATE ReachabilityTests SET IsSynced = Synced WHERE Synced IS NOT NULL;
                            ";
                            addColumn.ExecuteNonQuery();
                            Logger.Info("Migrated ReachabilityTests: Added IsSynced column and copied data from Synced");
                        }
                        // If neither exists, add IsSynced
                        else if (!columns.Contains("IsSynced") && !columns.Contains("Synced"))
                        {
                            var addColumn = connection.CreateCommand();
                            addColumn.CommandText = "ALTER TABLE ReachabilityTests ADD COLUMN IsSynced INTEGER NOT NULL DEFAULT 0";
                            addColumn.ExecuteNonQuery();
                            Logger.Info("Added IsSynced column to ReachabilityTests table");
                        }
                    }
                }
                catch (Exception ex)
                {
                    Logger.Warn(ex, "Failed to migrate ReachabilityTests table - continuing");
                }

                // Check if Assets table exists first
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
                    // Check if Assets table needs migration (add metadata columns)
                    var columns = new HashSet<string>();
                    try
                    {
                        var checkCommand = connection.CreateCommand();
                        checkCommand.CommandText = "PRAGMA table_info(Assets)";
                        
                        using (var reader = checkCommand.ExecuteReader())
                        {
                            while (reader.Read())
                            {
                                columns.Add(reader.GetString(1)); // Column name is at index 1
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        Logger.Warn(ex, "Failed to check Assets table columns, will attempt to add all columns");
                        // If check fails, assume columns don't exist and try to add them
                        columns.Clear();
                    }

                    // Add missing columns to Assets table - always try to add, handle "column already exists" gracefully
                    // This ensures columns exist even if the check failed or was incomplete
                    var assetsColumnsToAdd = new[] { "HardwareId", "MachineName", "Username", "UserId", "Ports" };
                    foreach (var columnName in assetsColumnsToAdd)
                    {
                        // Always try to add the column - if it already exists, SQLite will throw an error which we'll catch
                        // This is safer than relying on the column check which might fail
                        try
                        {
                            var addColumn = connection.CreateCommand();
                            addColumn.CommandText = $"ALTER TABLE Assets ADD COLUMN {columnName} TEXT";
                            addColumn.ExecuteNonQuery();
                            Logger.Info($"Successfully added {columnName} column to Assets table");
                        }
                        catch (Microsoft.Data.Sqlite.SqliteException sqlEx) when (sqlEx.Message.Contains("duplicate column") || sqlEx.Message.Contains("already exists") || sqlEx.SqliteErrorCode == 1)
                        {
                            // Column already exists - this is fine, just log it
                            Logger.Debug($"{columnName} column already exists in Assets table");
                        }
                        catch (Exception ex)
                        {
                            Logger.Warn(ex, $"Failed to add {columnName} column to Assets table (may already exist)");
                            // Don't throw - continue with other columns
                        }
                    }
                }

                // Check if Ports table needs migration (add metadata columns)
                // First check if Ports table exists
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
                                portsColumns.Add(portsReader.GetString(1)); // Column name is at index 1
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        Logger.Warn(ex, "Failed to check Ports table columns, will attempt to add all columns");
                        // If check fails, assume columns don't exist and try to add them
                        portsColumns.Clear();
                    }

                    // Add missing columns to Ports table - use try-catch for each to handle "column already exists" errors
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
                                // Column already exists - this is fine, just log it
                                Logger.Info($"{columnName} column already exists in Ports table");
                            }
                            catch (Exception ex)
                            {
                                Logger.Error(ex, $"Failed to add {columnName} column to Ports table");
                                // Don't throw - continue with other columns
                            }
                        }
                    }
                }
                else
                {
                    Logger.Info("Ports table does not exist yet - will be created with all columns");
                }

                Logger.Info("Database migration completed successfully");
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "Error during database migration");
                // Don't throw - allow initialization to continue
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
                    CREATE TABLE IF NOT EXISTS AttackLogs (
                        Id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ProjectName TEXT,
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
                        SyncedAt TEXT,
                        IsSynced INTEGER NOT NULL DEFAULT 0,
                        HardwareId TEXT,
                        MachineName TEXT,
                        Username TEXT,
                        UserId TEXT
                    );
                    
                    CREATE TABLE IF NOT EXISTS Assets (
                        Id INTEGER PRIMARY KEY AUTOINCREMENT,
                        HostIp TEXT NOT NULL,
                        HostName TEXT,
                        MacAddress TEXT,
                        Vendor TEXT,
                        IsOnline INTEGER NOT NULL DEFAULT 0,
                        PingTime INTEGER,
                        ScanTime TEXT NOT NULL,
                        ProjectName TEXT,
                        Synced INTEGER NOT NULL DEFAULT 0,
                        CreatedAt TEXT NOT NULL,
                        SyncedAt TEXT,
                        HardwareId TEXT,
                        MachineName TEXT,
                        Username TEXT,
                        UserId TEXT,
                        Ports TEXT
                    );
                    
                    CREATE TABLE IF NOT EXISTS Ports (
                        Id INTEGER PRIMARY KEY AUTOINCREMENT,
                        AssetId INTEGER,
                        HostIp TEXT NOT NULL,
                        Port INTEGER NOT NULL,
                        Protocol TEXT NOT NULL DEFAULT 'TCP',
                        Service TEXT,
                        Banner TEXT,
                        ScanTime TEXT NOT NULL,
                        ProjectName TEXT,
                        Synced INTEGER NOT NULL DEFAULT 0,
                        CreatedAt TEXT NOT NULL,
                        SyncedAt TEXT,
                        HardwareId TEXT,
                        MachineName TEXT,
                        Username TEXT,
                        UserId TEXT,
                        FOREIGN KEY (AssetId) REFERENCES Assets(Id) ON DELETE CASCADE
                    );
                    
                    CREATE TABLE IF NOT EXISTS ReachabilityTests (
                        Id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ProjectName TEXT,
                        AnalysisMode TEXT NOT NULL,
                        VantagePointName TEXT NOT NULL,
                        SourceNicId TEXT NOT NULL,
                        SourceIp TEXT NOT NULL,
                        TargetNetworkName TEXT,
                        TargetCidr TEXT,
                        BoundaryGatewayIp TEXT,
                        BoundaryVendor TEXT,
                        ExternalTestIp TEXT,
                        IsSynced INTEGER NOT NULL DEFAULT 0,
                        CreatedAt TEXT NOT NULL,
                        SyncedAt TEXT,
                        HardwareId TEXT,
                        MachineName TEXT,
                        Username TEXT,
                        UserId TEXT
                    );
                    
                    CREATE TABLE IF NOT EXISTS ReachabilityIcmpResults (
                        Id INTEGER PRIMARY KEY AUTOINCREMENT,
                        TestId INTEGER NOT NULL,
                        TargetIp TEXT NOT NULL,
                        Role TEXT NOT NULL,
                        Reachable INTEGER NOT NULL DEFAULT 0,
                        Sent INTEGER NOT NULL DEFAULT 0,
                        Received INTEGER NOT NULL DEFAULT 0,
                        AvgRttMs INTEGER,
                        CreatedAt TEXT NOT NULL,
                        FOREIGN KEY (TestId) REFERENCES ReachabilityTests(Id) ON DELETE CASCADE
                    );
                    
                    CREATE TABLE IF NOT EXISTS ReachabilityTcpResults (
                        Id INTEGER PRIMARY KEY AUTOINCREMENT,
                        TestId INTEGER NOT NULL,
                        TargetIp TEXT NOT NULL,
                        Port INTEGER NOT NULL,
                        State TEXT NOT NULL,
                        RttMs INTEGER NOT NULL DEFAULT 0,
                        ErrorMessage TEXT,
                        CreatedAt TEXT NOT NULL,
                        FOREIGN KEY (TestId) REFERENCES ReachabilityTests(Id) ON DELETE CASCADE
                    );
                    
                    CREATE TABLE IF NOT EXISTS ReachabilityPathHops (
                        Id INTEGER PRIMARY KEY AUTOINCREMENT,
                        TestId INTEGER NOT NULL,
                        TargetIp TEXT NOT NULL,
                        HopNumber INTEGER NOT NULL,
                        HopIp TEXT,
                        RttMs INTEGER,
                        Hostname TEXT,
                        CreatedAt TEXT NOT NULL,
                        FOREIGN KEY (TestId) REFERENCES ReachabilityTests(Id) ON DELETE CASCADE
                    );
                    
                    CREATE TABLE IF NOT EXISTS ReachabilityDeeperScans (
                        Id INTEGER PRIMARY KEY AUTOINCREMENT,
                        TestId INTEGER NOT NULL,
                        TargetIp TEXT NOT NULL,
                        PortStates TEXT NOT NULL,
                        Summary TEXT,
                        CreatedAt TEXT NOT NULL,
                        FOREIGN KEY (TestId) REFERENCES ReachabilityTests(Id) ON DELETE CASCADE
                    );
                    
                    CREATE TABLE IF NOT EXISTS ReachabilitySnmpWalks (
                        Id INTEGER PRIMARY KEY AUTOINCREMENT,
                        TestId INTEGER NOT NULL,
                        TargetIp TEXT NOT NULL,
                        Port INTEGER NOT NULL,
                        Success INTEGER NOT NULL DEFAULT 0,
                        SuccessfulCommunity TEXT,
                        SuccessfulOids TEXT NOT NULL,
                        Attempts INTEGER NOT NULL DEFAULT 0,
                        DurationMs INTEGER NOT NULL DEFAULT 0,
                        CreatedAt TEXT NOT NULL,
                        FOREIGN KEY (TestId) REFERENCES ReachabilityTests(Id) ON DELETE CASCADE
                    );
                ";
                command.ExecuteNonQuery();
                Logger.Info("Database tables created");
                
                // Run migrations AFTER tables are created
                MigrateDatabase(connection);
                
                Logger.Info("Database initialized successfully");
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "Failed to initialize database");
                throw;
            }
        }

        /// <summary>
        /// Ensures database migrations are run. Can be called before queries to ensure schema is up to date.
        /// </summary>
        private async Task EnsureMigrationsAsync(SqliteConnection connection)
        {
            try
            {
                // Run migration synchronously on the connection
                // Since we're already in an async context, we'll use Task.Run to avoid blocking
                await Task.Run(() =>
                {
                    MigrateDatabase(connection);
                });
            }
            catch (Exception ex)
            {
                Logger.Warn(ex, "Failed to ensure migrations - continuing anyway");
                // Don't throw - allow query to proceed
            }
        }

        public async Task<long> SaveAttackLogAsync(AttackLogEntry entry)
        {
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();
                
                // Ensure migrations are run before inserting
                await EnsureMigrationsAsync(connection);

                var command = connection.CreateCommand();
                command.CommandText = @"
                    INSERT INTO AttackLogs 
                    (ProjectName, AttackType, Protocol, SourceIp, SourceMac, TargetIp, TargetMac, TargetPort, 
                     TargetRateMbps, PacketsSent, DurationSeconds, StartTime, StopTime, Note, LogContent, CreatedAt, IsSynced,
                     HardwareId, MachineName, Username, UserId)
                    VALUES 
                    (@ProjectName, @AttackType, @Protocol, @SourceIp, @SourceMac, @TargetIp, @TargetMac, @TargetPort,
                     @TargetRateMbps, @PacketsSent, @DurationSeconds, @StartTime, @StopTime, @Note, @LogContent, @CreatedAt, 0,
                     @HardwareId, @MachineName, @Username, @UserId);
                    SELECT last_insert_rowid();
                ";

                command.Parameters.AddWithValue("@ProjectName", entry.ProjectName ?? (object)DBNull.Value);
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

        public async Task<List<AttackLogEntry>> GetUnsyncedLogsAsync(List<long>? selectedIds = null)
        {
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();

                // Ensure migrations are run before querying
                await EnsureMigrationsAsync(connection);

                // Check if HardwareId column exists
                bool hasHardwareId = false;
                try
                {
                    var checkCommand = connection.CreateCommand();
                    checkCommand.CommandText = "PRAGMA table_info(AttackLogs)";
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
                        SELECT Id, ProjectName, AttackType, Protocol, SourceIp, SourceMac, TargetIp, TargetMac, TargetPort,
                               TargetRateMbps, PacketsSent, DurationSeconds, StartTime, StopTime, Note, LogContent, 
                               CreatedAt, SyncedAt, IsSynced, HardwareId, MachineName, Username, UserId
                        FROM AttackLogs
                        WHERE IsSynced = 0";
                }
                else
                {
                    query = @"
                        SELECT Id, ProjectName, AttackType, Protocol, SourceIp, SourceMac, TargetIp, TargetMac, TargetPort,
                               TargetRateMbps, PacketsSent, DurationSeconds, StartTime, StopTime, Note, LogContent, 
                               CreatedAt, SyncedAt, IsSynced
                        FROM AttackLogs
                        WHERE IsSynced = 0";
                }
                
                if (selectedIds != null && selectedIds.Count > 0)
                {
                    var ids = string.Join(",", selectedIds);
                    query += $" AND Id IN ({ids})";
                }
                
                query += " ORDER BY CreatedAt ASC";
                
                command.CommandText = query;

                var logs = new List<AttackLogEntry>();
                using var reader = await command.ExecuteReaderAsync();
                while (await reader.ReadAsync())
                {
                    logs.Add(MapReaderToEntry(reader));
                }

                return logs;
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "Failed to get unsynced logs");
                throw;
            }
        }

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

                // Use parameterized query to prevent SQL injection
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

                // Use parameterized query to prevent SQL injection
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
                // Get all ports for this host
                var ports = await GetPortsByHostIpAsync(hostIp);
                
                // Generate ports display string - ONLY port numbers, NO banners
                // Banners are stored separately in the ports table
                string portsDisplay = null;
                if (ports != null && ports.Count > 0)
                {
                    // Only include port/protocol, no banners
                    portsDisplay = string.Join(", ", ports.OrderBy(p => p.Port).Select(p => $"{p.Port}/{p.Protocol}"));
                }

                // Update asset's Ports column
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
                // Don't throw - this is a non-critical update
            }
        }

        public async Task<long> SaveAssetAsync(AssetEntry asset)
        {
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();
                
                // Ensure migrations are run before inserting
                await EnsureMigrationsAsync(connection);

                // Check if asset already exists
                var existingAssetId = await GetAssetIdByHostIpAsync(asset.HostIp);
                
                if (existingAssetId.HasValue)
                {
                    // Update existing asset and mark as unsynced
                    var updateCommand = connection.CreateCommand();
                    updateCommand.CommandText = @"
                        UPDATE Assets 
                        SET HostName = @HostName, MacAddress = @MacAddress, Vendor = @Vendor, 
                            IsOnline = @IsOnline, PingTime = @PingTime, ScanTime = @ScanTime,
                            Ports = @Ports, Synced = 0, SyncedAt = NULL
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

                    await updateCommand.ExecuteNonQueryAsync();
                    Logger.Info($"Updated existing asset {existingAssetId.Value} for {asset.HostIp} and marked as unsynced");
                    return existingAssetId.Value;
                }
                else
                {
                    // Insert new asset
                    var command = connection.CreateCommand();
                    command.CommandText = @"
                        INSERT INTO Assets 
                        (HostIp, HostName, MacAddress, Vendor, IsOnline, PingTime, ScanTime, ProjectName, CreatedAt, Synced,
                         HardwareId, MachineName, Username, UserId, Ports)
                        VALUES 
                        (@HostIp, @HostName, @MacAddress, @Vendor, @IsOnline, @PingTime, @ScanTime, @ProjectName, @CreatedAt, 0,
                         @HardwareId, @MachineName, @Username, @UserId, @Ports);
                        SELECT last_insert_rowid();
                    ";

                    command.Parameters.AddWithValue("@HostIp", asset.HostIp);
                    command.Parameters.AddWithValue("@HostName", asset.HostName ?? (object)DBNull.Value);
                    command.Parameters.AddWithValue("@MacAddress", asset.MacAddress ?? (object)DBNull.Value);
                    command.Parameters.AddWithValue("@Vendor", asset.Vendor ?? (object)DBNull.Value);
                    command.Parameters.AddWithValue("@IsOnline", asset.IsOnline ? 1 : 0);
                    command.Parameters.AddWithValue("@PingTime", asset.PingTime ?? (object)DBNull.Value);
                    command.Parameters.AddWithValue("@ScanTime", asset.ScanTime.ToString("O"));
                    command.Parameters.AddWithValue("@ProjectName", asset.ProjectName ?? (object)DBNull.Value);
                    command.Parameters.AddWithValue("@CreatedAt", asset.CreatedAt.ToString("O"));
                    command.Parameters.AddWithValue("@HardwareId", asset.HardwareId ?? (object)DBNull.Value);
                    command.Parameters.AddWithValue("@MachineName", asset.MachineName ?? (object)DBNull.Value);
                    command.Parameters.AddWithValue("@Username", asset.Username ?? (object)DBNull.Value);
                    command.Parameters.AddWithValue("@UserId", asset.UserId?.ToString() ?? (object)DBNull.Value);
                    command.Parameters.AddWithValue("@Ports", asset.Ports ?? (object)DBNull.Value);

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

        public async Task SavePortAsync(PortEntry port, bool markAssetUnsynced = true)
        {
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();

                // Check if port already exists for this asset/host
                var checkCommand = connection.CreateCommand();
                checkCommand.CommandText = @"
                    SELECT Id FROM Ports 
                    WHERE HostIp = @HostIp AND Port = @Port AND Protocol = @Protocol
                    LIMIT 1
                ";
                checkCommand.Parameters.AddWithValue("@HostIp", port.HostIp);
                checkCommand.Parameters.AddWithValue("@Port", port.Port);
                checkCommand.Parameters.AddWithValue("@Protocol", port.Protocol);

                var existingPortId = await checkCommand.ExecuteScalarAsync();

                if (existingPortId != null && existingPortId != DBNull.Value)
                {
                    // Update existing port - always update banner even if it was previously empty
                    var updateCommand = connection.CreateCommand();
                    updateCommand.CommandText = @"
                        UPDATE Ports 
                        SET Service = @Service, Banner = @Banner, ScanTime = @ScanTime, Synced = 0
                        WHERE Id = @Id
                    ";
                    updateCommand.Parameters.AddWithValue("@Id", Convert.ToInt64(existingPortId));
                    updateCommand.Parameters.AddWithValue("@Service", port.Service ?? (object)DBNull.Value);
                    // Always update banner - if it's empty/null, set to NULL; otherwise set to the banner value
                    var bannerValue = string.IsNullOrWhiteSpace(port.Banner) ? (object)DBNull.Value : port.Banner.Trim();
                    updateCommand.Parameters.AddWithValue("@Banner", bannerValue);
                    updateCommand.Parameters.AddWithValue("@ScanTime", port.ScanTime.ToString("O"));

                    await updateCommand.ExecuteNonQueryAsync();
                    Logger.Info($"Updated existing port {port.Port}/{port.Protocol} for {port.HostIp} (Banner: {(string.IsNullOrWhiteSpace(port.Banner) ? "None" : port.Banner.Substring(0, Math.Min(50, port.Banner.Length)) + "...")})");
                }
                else
                {
                    // Insert new port
                    var command = connection.CreateCommand();
                    command.CommandText = @"
                        INSERT INTO Ports 
                        (AssetId, HostIp, Port, Protocol, Service, Banner, ScanTime, ProjectName, CreatedAt, Synced,
                         HardwareId, MachineName, Username, UserId)
                        VALUES 
                        (@AssetId, @HostIp, @Port, @Protocol, @Service, @Banner, @ScanTime, @ProjectName, @CreatedAt, 0,
                         @HardwareId, @MachineName, @Username, @UserId);
                    ";

                    command.Parameters.AddWithValue("@AssetId", port.AssetId > 0 ? (object)port.AssetId : DBNull.Value);
                    command.Parameters.AddWithValue("@HostIp", port.HostIp);
                    command.Parameters.AddWithValue("@Port", port.Port);
                    command.Parameters.AddWithValue("@Protocol", port.Protocol);
                    command.Parameters.AddWithValue("@Service", port.Service ?? (object)DBNull.Value);
                    // Always save banner - if it's empty/null, set to NULL; otherwise set to the trimmed banner value
                    var bannerValue = string.IsNullOrWhiteSpace(port.Banner) ? (object)DBNull.Value : port.Banner.Trim();
                    command.Parameters.AddWithValue("@Banner", bannerValue);
                    command.Parameters.AddWithValue("@ScanTime", port.ScanTime.ToString("O"));
                    command.Parameters.AddWithValue("@ProjectName", port.ProjectName ?? (object)DBNull.Value);
                    command.Parameters.AddWithValue("@CreatedAt", port.CreatedAt.ToString("O"));
                    command.Parameters.AddWithValue("@HardwareId", port.HardwareId ?? (object)DBNull.Value);
                    command.Parameters.AddWithValue("@MachineName", port.MachineName ?? (object)DBNull.Value);
                    command.Parameters.AddWithValue("@Username", port.Username ?? (object)DBNull.Value);
                    command.Parameters.AddWithValue("@UserId", port.UserId?.ToString() ?? (object)DBNull.Value);

                    await command.ExecuteNonQueryAsync();
                    Logger.Info($"Inserted new port {port.Port}/{port.Protocol} for {port.HostIp}");
                }

                // Update asset's Ports column with all ports for this host
                if (port.AssetId > 0)
                {
                    await UpdateAssetPortsColumnAsync(port.AssetId, port.HostIp);
                }
                else if (!string.IsNullOrEmpty(port.HostIp))
                {
                    // If AssetId is not set, try to find asset by HostIp and update it
                    var assetId = await GetAssetIdByHostIpAsync(port.HostIp);
                    if (assetId.HasValue)
                    {
                        await UpdateAssetPortsColumnAsync(assetId.Value, port.HostIp);
                    }
                }

                // Mark asset as unsynced when ports are added/updated
                if (markAssetUnsynced && port.AssetId > 0)
                {
                    await MarkAssetAsUnsyncedAsync(port.AssetId);
                }
                else if (markAssetUnsynced && !string.IsNullOrEmpty(port.HostIp))
                {
                    // If AssetId is not set, try to find asset by HostIp and mark as unsynced
                    var assetId = await GetAssetIdByHostIpAsync(port.HostIp);
                    if (assetId.HasValue)
                    {
                        await MarkAssetAsUnsyncedAsync(assetId.Value);
                    }
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
                
                // Ensure migrations are run before querying
                await EnsureMigrationsAsync(connection);

                // Check if HardwareId column exists
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
                        WHERE HostIp = @HostIp
                        ORDER BY Port ASC
                    ";
                }
                else
                {
                    query = @"
                        SELECT Id, AssetId, HostIp, Port, Protocol, Service, Banner, ScanTime, ProjectName, 
                               CreatedAt, Synced
                        FROM Ports
                        WHERE HostIp = @HostIp
                        ORDER BY Port ASC
                    ";
                }
                command.CommandText = query;
                command.Parameters.AddWithValue("@HostIp", hostIp);

                var ports = new List<PortEntry>();
                using (var portsReader = await command.ExecuteReaderAsync())
                {
                    while (await portsReader.ReadAsync())
                    {
                        var port = new PortEntry
                        {
                            Id = portsReader.GetInt64(0),
                            AssetId = portsReader.IsDBNull(1) ? 0 : portsReader.GetInt64(1),
                            HostIp = portsReader.GetString(2),
                            Port = portsReader.GetInt32(3),
                            Protocol = portsReader.GetString(4),
                            Service = portsReader.IsDBNull(5) ? null : portsReader.GetString(5),
                            Banner = portsReader.IsDBNull(6) ? null : portsReader.GetString(6),
                            ScanTime = DateTime.Parse(portsReader.GetString(7)),
                            ProjectName = portsReader.IsDBNull(8) ? null : portsReader.GetString(8),
                            CreatedAt = DateTime.Parse(portsReader.GetString(9)),
                            Synced = portsReader.GetInt32(10) == 1
                        };
                        
                        // Only set metadata fields if they exist in the query result
                        if (hasHardwareId && portsReader.FieldCount > 11)
                        {
                            port.HardwareId = portsReader.IsDBNull(11) ? null : portsReader.GetString(11);
                            port.MachineName = portsReader.IsDBNull(12) ? null : portsReader.GetString(12);
                            port.Username = portsReader.IsDBNull(13) ? null : portsReader.GetString(13);
                            port.UserId = portsReader.IsDBNull(14) ? null : (Guid.TryParse(portsReader.GetString(14), out var userId) ? userId : (Guid?)null);
                        }
                        
                        ports.Add(port);
                    }
                }

                return ports;
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "Failed to get ports by host IP");
                throw;
            }
        }

        public async Task<List<PortEntry>> GetUnsyncedPortsByHostIpAsync(string hostIp)
        {
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();
                
                // Ensure migrations are run before querying
                await EnsureMigrationsAsync(connection);

                // Check if HardwareId column exists
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

                var ports = new List<PortEntry>();
                using (var portsReader = await command.ExecuteReaderAsync())
                {
                    while (await portsReader.ReadAsync())
                    {
                        var port = new PortEntry
                        {
                            Id = portsReader.GetInt64(0),
                            AssetId = portsReader.IsDBNull(1) ? 0 : portsReader.GetInt64(1),
                            HostIp = portsReader.GetString(2),
                            Port = portsReader.GetInt32(3),
                            Protocol = portsReader.GetString(4),
                            Service = portsReader.IsDBNull(5) ? null : portsReader.GetString(5),
                            Banner = portsReader.IsDBNull(6) ? null : portsReader.GetString(6),
                            ScanTime = DateTime.Parse(portsReader.GetString(7)),
                            ProjectName = portsReader.IsDBNull(8) ? null : portsReader.GetString(8),
                            CreatedAt = DateTime.Parse(portsReader.GetString(9)),
                            Synced = portsReader.GetInt32(10) == 1
                        };
                        
                        // Only set metadata fields if they exist in the query result
                        if (hasHardwareId && portsReader.FieldCount > 11)
                        {
                            port.HardwareId = portsReader.IsDBNull(11) ? null : portsReader.GetString(11);
                            port.MachineName = portsReader.IsDBNull(12) ? null : portsReader.GetString(12);
                            port.Username = portsReader.IsDBNull(13) ? null : portsReader.GetString(13);
                            port.UserId = portsReader.IsDBNull(14) ? null : (Guid.TryParse(portsReader.GetString(14), out var userId) ? userId : (Guid?)null);
                        }
                        
                        ports.Add(port);
                    }
                }

                return ports;
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

                // Check if SyncedAt column exists
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

        public async Task<List<AssetEntry>> GetUnsyncedAssetsAsync(List<long>? selectedIds = null)
        {
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();
                
                // Ensure migrations are run before querying
                await EnsureMigrationsAsync(connection);

                // Check if HardwareId column exists - if not, use a query without it
                bool hasHardwareId = false;
                try
                {
                    var checkCommand = connection.CreateCommand();
                    checkCommand.CommandText = "PRAGMA table_info(Assets)";
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
                    // If check fails, assume column doesn't exist
                    hasHardwareId = false;
                }

                var command = connection.CreateCommand();
                string query;
                if (hasHardwareId)
                {
                    query = @"
                        SELECT Id, HostIp, HostName, MacAddress, Vendor, IsOnline, PingTime, ScanTime, ProjectName, Synced, CreatedAt, SyncedAt,
                               HardwareId, MachineName, Username, UserId, Ports
                        FROM Assets
                        WHERE Synced = 0";
                }
                else
                {
                    // Fallback query without HardwareId columns (will be added by migration)
                    query = @"
                        SELECT Id, HostIp, HostName, MacAddress, Vendor, IsOnline, PingTime, ScanTime, ProjectName, Synced, CreatedAt, SyncedAt
                        FROM Assets
                        WHERE Synced = 0";
                }
                
                if (selectedIds != null && selectedIds.Count > 0)
                {
                    var ids = string.Join(",", selectedIds);
                    query += $" AND Id IN ({ids})";
                }
                
                query += " ORDER BY CreatedAt ASC";
                
                command.CommandText = query;

                var assets = new List<AssetEntry>();
                using var reader = await command.ExecuteReaderAsync();
                while (await reader.ReadAsync())
                {
                    assets.Add(MapReaderToAsset(reader));
                }

                return assets;
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "Failed to get unsynced assets");
                throw;
            }
        }

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

        private AssetEntry MapReaderToAsset(DbDataReader reader)
        {
            return new AssetEntry
            {
                Id = reader.GetInt64(0),
                HostIp = reader.GetString(1),
                HostName = reader.IsDBNull(2) ? null : reader.GetString(2),
                MacAddress = reader.IsDBNull(3) ? null : reader.GetString(3),
                Vendor = reader.IsDBNull(4) ? null : reader.GetString(4),
                IsOnline = reader.GetInt32(5) == 1,
                PingTime = reader.IsDBNull(6) ? null : reader.GetInt32(6),
                ScanTime = DateTime.Parse(reader.GetString(7)),
                ProjectName = reader.IsDBNull(8) ? null : reader.GetString(8),
                Synced = reader.GetInt32(9) == 1,
                CreatedAt = DateTime.Parse(reader.GetString(10)),
                SyncedAt = reader.IsDBNull(11) ? null : DateTime.Parse(reader.GetString(11)),
                HardwareId = reader.IsDBNull(12) ? null : reader.GetString(12),
                MachineName = reader.IsDBNull(13) ? null : reader.GetString(13),
                Username = reader.IsDBNull(14) ? null : reader.GetString(14),
                UserId = reader.IsDBNull(15) ? null : (Guid.TryParse(reader.GetString(15), out var userId) ? userId : (Guid?)null),
                Ports = reader.FieldCount > 16 && !reader.IsDBNull(16) ? reader.GetString(16) : null
            };
        }

        /// <summary>
        /// Save a complete reachability test result to the database
        /// </summary>
        public async Task<long> SaveReachabilityTestAsync(
            Models.ReachabilityWizardResult result,
            string? projectName = null,
            string? hardwareId = null,
            string? machineName = null,
            string? username = null,
            Guid? userId = null)
        {
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();
                
                await EnsureMigrationsAsync(connection);

                // Start transaction
                using var transaction = connection.BeginTransaction();

                try
                {
                    // Insert main test record
                    var testCommand = connection.CreateCommand();
                    testCommand.Transaction = transaction;
                    testCommand.CommandText = @"
                        INSERT INTO ReachabilityTests 
                        (ProjectName, AnalysisMode, VantagePointName, SourceNicId, SourceIp, 
                         TargetNetworkName, TargetCidr, BoundaryGatewayIp, BoundaryVendor, ExternalTestIp,
                         CreatedAt, IsSynced, HardwareId, MachineName, Username, UserId)
                        VALUES 
                        (@ProjectName, @AnalysisMode, @VantagePointName, @SourceNicId, @SourceIp,
                         @TargetNetworkName, @TargetCidr, @BoundaryGatewayIp, @BoundaryVendor, @ExternalTestIp,
                         @CreatedAt, 0, @HardwareId, @MachineName, @Username, @UserId);
                        SELECT last_insert_rowid();
                    ";

                    var context = result.Context;
                    testCommand.Parameters.AddWithValue("@ProjectName", projectName ?? (object)DBNull.Value);
                    testCommand.Parameters.AddWithValue("@AnalysisMode", context.Mode.ToString());
                    testCommand.Parameters.AddWithValue("@VantagePointName", context.VantagePointName);
                    testCommand.Parameters.AddWithValue("@SourceNicId", context.SourceNicId);
                    testCommand.Parameters.AddWithValue("@SourceIp", context.SourceIp.ToString());
                    testCommand.Parameters.AddWithValue("@TargetNetworkName", context.TargetNetworkName ?? (object)DBNull.Value);
                    testCommand.Parameters.AddWithValue("@TargetCidr", context.TargetCidr ?? (object)DBNull.Value);
                    testCommand.Parameters.AddWithValue("@BoundaryGatewayIp", result.BoundaryGatewayIp?.ToString() ?? (object)DBNull.Value);
                    testCommand.Parameters.AddWithValue("@BoundaryVendor", result.BoundaryVendor ?? (object)DBNull.Value);
                    testCommand.Parameters.AddWithValue("@ExternalTestIp", context.ExternalTestIp?.ToString() ?? (object)DBNull.Value);
                    testCommand.Parameters.AddWithValue("@CreatedAt", DateTime.UtcNow.ToString("O"));
                    testCommand.Parameters.AddWithValue("@HardwareId", hardwareId ?? (object)DBNull.Value);
                    testCommand.Parameters.AddWithValue("@MachineName", machineName ?? (object)DBNull.Value);
                    testCommand.Parameters.AddWithValue("@Username", username ?? (object)DBNull.Value);
                    testCommand.Parameters.AddWithValue("@UserId", userId?.ToString() ?? (object)DBNull.Value);

                    var testId = (long)(await testCommand.ExecuteScalarAsync())!;

                    var createdAt = DateTime.UtcNow.ToString("O");

                    // Insert ICMP results
                    foreach (var icmp in result.IcmpResults)
                    {
                        var icmpCommand = connection.CreateCommand();
                        icmpCommand.Transaction = transaction;
                        icmpCommand.CommandText = @"
                            INSERT INTO ReachabilityIcmpResults 
                            (TestId, TargetIp, Role, Reachable, Sent, Received, AvgRttMs, CreatedAt)
                            VALUES 
                            (@TestId, @TargetIp, @Role, @Reachable, @Sent, @Received, @AvgRttMs, @CreatedAt);
                        ";
                        icmpCommand.Parameters.AddWithValue("@TestId", testId);
                        icmpCommand.Parameters.AddWithValue("@TargetIp", icmp.TargetIp.ToString());
                        icmpCommand.Parameters.AddWithValue("@Role", icmp.Role);
                        icmpCommand.Parameters.AddWithValue("@Reachable", icmp.Reachable ? 1 : 0);
                        icmpCommand.Parameters.AddWithValue("@Sent", icmp.Sent);
                        icmpCommand.Parameters.AddWithValue("@Received", icmp.Received);
                        icmpCommand.Parameters.AddWithValue("@AvgRttMs", icmp.AvgRttMs ?? (object)DBNull.Value);
                        icmpCommand.Parameters.AddWithValue("@CreatedAt", createdAt);
                        await icmpCommand.ExecuteNonQueryAsync();
                    }

                    // Insert TCP results
                    foreach (var tcp in result.TcpResults)
                    {
                        var tcpCommand = connection.CreateCommand();
                        tcpCommand.Transaction = transaction;
                        tcpCommand.CommandText = @"
                            INSERT INTO ReachabilityTcpResults 
                            (TestId, TargetIp, Port, State, RttMs, ErrorMessage, CreatedAt)
                            VALUES 
                            (@TestId, @TargetIp, @Port, @State, @RttMs, @ErrorMessage, @CreatedAt);
                        ";
                        tcpCommand.Parameters.AddWithValue("@TestId", testId);
                        tcpCommand.Parameters.AddWithValue("@TargetIp", tcp.TargetIp.ToString());
                        tcpCommand.Parameters.AddWithValue("@Port", tcp.Port);
                        tcpCommand.Parameters.AddWithValue("@State", tcp.State.ToString());
                        tcpCommand.Parameters.AddWithValue("@RttMs", tcp.RttMs);
                        tcpCommand.Parameters.AddWithValue("@ErrorMessage", tcp.ErrorMessage ?? (object)DBNull.Value);
                        tcpCommand.Parameters.AddWithValue("@CreatedAt", createdAt);
                        await tcpCommand.ExecuteNonQueryAsync();
                    }

                    // Insert path hops
                    if (result.PathResult != null)
                    {
                        foreach (var hop in result.PathResult.Hops)
                        {
                            var hopCommand = connection.CreateCommand();
                            hopCommand.Transaction = transaction;
                            hopCommand.CommandText = @"
                                INSERT INTO ReachabilityPathHops 
                                (TestId, TargetIp, HopNumber, HopIp, RttMs, Hostname, CreatedAt)
                                VALUES 
                                (@TestId, @TargetIp, @HopNumber, @HopIp, @RttMs, @Hostname, @CreatedAt);
                            ";
                            hopCommand.Parameters.AddWithValue("@TestId", testId);
                            hopCommand.Parameters.AddWithValue("@TargetIp", result.PathResult.TargetIp.ToString());
                            hopCommand.Parameters.AddWithValue("@HopNumber", hop.HopNumber);
                            hopCommand.Parameters.AddWithValue("@HopIp", hop.HopIp?.ToString() ?? (object)DBNull.Value);
                            hopCommand.Parameters.AddWithValue("@RttMs", hop.RttMs ?? (object)DBNull.Value);
                            hopCommand.Parameters.AddWithValue("@Hostname", hop.Hostname ?? (object)DBNull.Value);
                            hopCommand.Parameters.AddWithValue("@CreatedAt", createdAt);
                            await hopCommand.ExecuteNonQueryAsync();
                        }
                    }

                    // Insert deeper scans
                    foreach (var scan in result.DeeperScanResults)
                    {
                        // Serialize port states to JSON
                        var portStatesJson = System.Text.Json.JsonSerializer.Serialize(scan.PortStates);
                        
                        var scanCommand = connection.CreateCommand();
                        scanCommand.Transaction = transaction;
                        scanCommand.CommandText = @"
                            INSERT INTO ReachabilityDeeperScans 
                            (TestId, TargetIp, PortStates, Summary, CreatedAt)
                            VALUES 
                            (@TestId, @TargetIp, @PortStates, @Summary, @CreatedAt);
                        ";
                        scanCommand.Parameters.AddWithValue("@TestId", testId);
                        scanCommand.Parameters.AddWithValue("@TargetIp", scan.TargetIp.ToString());
                        scanCommand.Parameters.AddWithValue("@PortStates", portStatesJson);
                        scanCommand.Parameters.AddWithValue("@Summary", scan.Summary ?? (object)DBNull.Value);
                        scanCommand.Parameters.AddWithValue("@CreatedAt", createdAt);
                        await scanCommand.ExecuteNonQueryAsync();
                    }

                    transaction.Commit();
                    Logger.Info($"Saved reachability test {testId} with {result.IcmpResults.Count} ICMP, {result.TcpResults.Count} TCP, {result.PathResult?.Hops.Count ?? 0} path hops, {result.DeeperScanResults.Count} deeper scans");
                    return testId;
                }
                catch
                {
                    transaction.Rollback();
                    throw;
                }
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "Failed to save reachability test");
                throw;
            }
        }

        /// <summary>
        /// Save SNMP walk result and link it to a reachability test (or create a new test entry)
        /// </summary>
        public async Task<long> SaveSnmpWalkResultAsync(
            Services.SnmpWalkResult snmpResult,
            long? existingTestId = null,
            string? projectName = null,
            string? hardwareId = null,
            string? machineName = null,
            string? username = null,
            Guid? userId = null)
        {
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();
                
                await EnsureMigrationsAsync(connection);

                using var transaction = connection.BeginTransaction();

                try
                {
                    long testId;
                    var createdAt = DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss");

                    if (existingTestId.HasValue)
                    {
                        // Link to existing test
                        testId = existingTestId.Value;
                    }
                    else
                    {
                        // Create a new minimal reachability test entry for SNMP walk
                        var testCommand = connection.CreateCommand();
                        testCommand.Transaction = transaction;
                        testCommand.CommandText = @"
                            INSERT INTO ReachabilityTests 
                            (ProjectName, AnalysisMode, VantagePointName, SourceNicId, SourceIp, 
                             TargetNetworkName, TargetCidr, BoundaryGatewayIp, BoundaryVendor, ExternalTestIp,
                             CreatedAt, IsSynced, HardwareId, MachineName, Username, UserId)
                            VALUES 
                            (@ProjectName, @AnalysisMode, @VantagePointName, @SourceNicId, @SourceIp,
                             @TargetNetworkName, @TargetCidr, @BoundaryGatewayIp, @BoundaryVendor, @ExternalTestIp,
                             @CreatedAt, 0, @HardwareId, @MachineName, @Username, @UserId);
                            SELECT last_insert_rowid();
                        ";

                        testCommand.Parameters.AddWithValue("@ProjectName", projectName ?? (object)DBNull.Value);
                        testCommand.Parameters.AddWithValue("@AnalysisMode", "BoundaryOnly");
                        testCommand.Parameters.AddWithValue("@VantagePointName", "SNMP Walk");
                        testCommand.Parameters.AddWithValue("@SourceNicId", "");
                        testCommand.Parameters.AddWithValue("@SourceIp", "");
                        testCommand.Parameters.AddWithValue("@TargetNetworkName", (object)DBNull.Value);
                        testCommand.Parameters.AddWithValue("@TargetCidr", (object)DBNull.Value);
                        testCommand.Parameters.AddWithValue("@BoundaryGatewayIp", snmpResult.TargetIp);
                        testCommand.Parameters.AddWithValue("@BoundaryVendor", (object)DBNull.Value);
                        testCommand.Parameters.AddWithValue("@ExternalTestIp", (object)DBNull.Value);
                        testCommand.Parameters.AddWithValue("@CreatedAt", createdAt);
                        testCommand.Parameters.AddWithValue("@HardwareId", hardwareId ?? (object)DBNull.Value);
                        testCommand.Parameters.AddWithValue("@MachineName", machineName ?? (object)DBNull.Value);
                        testCommand.Parameters.AddWithValue("@Username", username ?? (object)DBNull.Value);
                        testCommand.Parameters.AddWithValue("@UserId", userId?.ToString() ?? (object)DBNull.Value);

                        var testIdObj = await testCommand.ExecuteScalarAsync();
                        testId = Convert.ToInt64(testIdObj);
                    }

                    // Serialize OIDs to JSON
                    var oidsJson = System.Text.Json.JsonSerializer.Serialize(snmpResult.SuccessfulOids);

                    // Insert SNMP walk result
                    var snmpCommand = connection.CreateCommand();
                    snmpCommand.Transaction = transaction;
                    snmpCommand.CommandText = @"
                        INSERT INTO ReachabilitySnmpWalks 
                        (TestId, TargetIp, Port, Success, SuccessfulCommunity, SuccessfulOids, Attempts, DurationMs, CreatedAt)
                        VALUES 
                        (@TestId, @TargetIp, @Port, @Success, @SuccessfulCommunity, @SuccessfulOids, @Attempts, @DurationMs, @CreatedAt);
                    ";

                    snmpCommand.Parameters.AddWithValue("@TestId", testId);
                    snmpCommand.Parameters.AddWithValue("@TargetIp", snmpResult.TargetIp);
                    snmpCommand.Parameters.AddWithValue("@Port", snmpResult.Port);
                    snmpCommand.Parameters.AddWithValue("@Success", snmpResult.Success ? 1 : 0);
                    snmpCommand.Parameters.AddWithValue("@SuccessfulCommunity", snmpResult.SuccessfulCommunity ?? (object)DBNull.Value);
                    snmpCommand.Parameters.AddWithValue("@SuccessfulOids", oidsJson);
                    snmpCommand.Parameters.AddWithValue("@Attempts", snmpResult.Attempts);
                    snmpCommand.Parameters.AddWithValue("@DurationMs", (long)snmpResult.Duration.TotalMilliseconds);
                    snmpCommand.Parameters.AddWithValue("@CreatedAt", createdAt);

                    await snmpCommand.ExecuteNonQueryAsync();

                    transaction.Commit();
                    Logger.Info($"Saved SNMP walk result for test {testId} on {snmpResult.TargetIp}:{snmpResult.Port}");
                    return testId;
                }
                catch
                {
                    transaction.Rollback();
                    throw;
                }
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "Failed to save SNMP walk result");
                throw;
            }
        }

        /// <summary>
        /// Get unsynced reachability tests
        /// </summary>
        public async Task<List<ReachabilityTestEntry>> GetUnsyncedReachabilityTestsAsync(List<long>? selectedIds = null)
        {
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();

                // Ensure migrations are run before querying
                await EnsureMigrationsAsync(connection);

                var command = connection.CreateCommand();
                string query = @"
                    SELECT Id, ProjectName, AnalysisMode, VantagePointName, SourceNicId, SourceIp,
                           TargetNetworkName, TargetCidr, BoundaryGatewayIp, BoundaryVendor, ExternalTestIp,
                           CreatedAt, IsSynced, HardwareId, MachineName, Username, UserId
                    FROM ReachabilityTests
                    WHERE IsSynced = 0
                ";

                if (selectedIds != null && selectedIds.Count > 0)
                {
                    var placeholders = string.Join(",", selectedIds.Select((_, i) => $"@Id{i}"));
                    query += $" AND Id IN ({placeholders})";
                }

                query += " ORDER BY CreatedAt ASC";

                command.CommandText = query;

                if (selectedIds != null && selectedIds.Count > 0)
                {
                    for (int i = 0; i < selectedIds.Count; i++)
                    {
                        command.Parameters.AddWithValue($"@Id{i}", selectedIds[i]);
                    }
                }

                var tests = new List<ReachabilityTestEntry>();
                using var reader = await command.ExecuteReaderAsync();
                while (await reader.ReadAsync())
                {
                    tests.Add(new ReachabilityTestEntry
                    {
                        Id = reader.GetInt64(0),
                        ProjectName = reader.IsDBNull(1) ? null : reader.GetString(1),
                        AnalysisMode = reader.GetString(2),
                        VantagePointName = reader.GetString(3),
                        SourceNicId = reader.GetString(4),
                        SourceIp = reader.GetString(5),
                        TargetNetworkName = reader.IsDBNull(6) ? null : reader.GetString(6),
                        TargetCidr = reader.IsDBNull(7) ? null : reader.GetString(7),
                        BoundaryGatewayIp = reader.IsDBNull(8) ? null : reader.GetString(8),
                        BoundaryVendor = reader.IsDBNull(9) ? null : reader.GetString(9),
                        ExternalTestIp = reader.IsDBNull(10) ? null : reader.GetString(10),
                        CreatedAt = DateTime.Parse(reader.GetString(11)),
                        IsSynced = reader.GetInt32(12) == 1,
                        Synced = reader.GetInt32(12) == 1,
                        HardwareId = reader.IsDBNull(13) ? null : reader.GetString(13),
                        MachineName = reader.IsDBNull(14) ? null : reader.GetString(14),
                        Username = reader.IsDBNull(15) ? null : reader.GetString(15),
                        UserId = reader.IsDBNull(16) ? null : (Guid.TryParse(reader.GetString(16), out var userId) ? userId : (Guid?)null)
                    });
                }

                return tests;
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "Failed to get unsynced reachability tests");
                throw;
            }
        }

        /// <summary>
        /// Get ICMP results for a specific test ID
        /// </summary>
        public async Task<List<ReachabilityIcmpResultEntry>> GetReachabilityIcmpResultsAsync(long testId)
        {
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();

                var command = connection.CreateCommand();
                command.CommandText = @"
                    SELECT Id, TestId, TargetIp, Role, Reachable, Sent, Received, AvgRttMs, CreatedAt
                    FROM ReachabilityIcmpResults
                    WHERE TestId = @TestId
                    ORDER BY CreatedAt ASC
                ";
                command.Parameters.AddWithValue("@TestId", testId);

                var results = new List<ReachabilityIcmpResultEntry>();
                using var reader = await command.ExecuteReaderAsync();
                while (await reader.ReadAsync())
                {
                    results.Add(new ReachabilityIcmpResultEntry
                    {
                        Id = reader.GetInt64(0),
                        TestId = reader.GetInt64(1),
                        TargetIp = reader.GetString(2),
                        Role = reader.GetString(3),
                        Reachable = reader.GetInt32(4) == 1,
                        Sent = reader.GetInt32(5),
                        Received = reader.GetInt32(6),
                        AvgRttMs = reader.IsDBNull(7) ? null : (long?)reader.GetInt64(7),
                        CreatedAt = DateTime.Parse(reader.GetString(8))
                    });
                }

                return results;
            }
            catch (Exception ex)
            {
                Logger.Error(ex, $"Failed to get ICMP results for test {testId}");
                throw;
            }
        }

        /// <summary>
        /// Get TCP results for a specific test ID
        /// </summary>
        public async Task<List<ReachabilityTcpResultEntry>> GetReachabilityTcpResultsAsync(long testId)
        {
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();

                var command = connection.CreateCommand();
                command.CommandText = @"
                    SELECT Id, TestId, TargetIp, Port, State, RttMs, ErrorMessage, CreatedAt
                    FROM ReachabilityTcpResults
                    WHERE TestId = @TestId
                    ORDER BY CreatedAt ASC
                ";
                command.Parameters.AddWithValue("@TestId", testId);

                var results = new List<ReachabilityTcpResultEntry>();
                using var reader = await command.ExecuteReaderAsync();
                while (await reader.ReadAsync())
                {
                    results.Add(new ReachabilityTcpResultEntry
                    {
                        Id = reader.GetInt64(0),
                        TestId = reader.GetInt64(1),
                        TargetIp = reader.GetString(2),
                        Port = reader.GetInt32(3),
                        State = reader.GetString(4),
                        RttMs = reader.GetInt64(5),
                        ErrorMessage = reader.IsDBNull(6) ? null : reader.GetString(6),
                        CreatedAt = DateTime.Parse(reader.GetString(7))
                    });
                }

                return results;
            }
            catch (Exception ex)
            {
                Logger.Error(ex, $"Failed to get TCP results for test {testId}");
                throw;
            }
        }

        /// <summary>
        /// Get path hops for a specific test ID
        /// </summary>
        public async Task<List<ReachabilityPathHopEntry>> GetReachabilityPathHopsAsync(long testId)
        {
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();

                var command = connection.CreateCommand();
                command.CommandText = @"
                    SELECT Id, TestId, TargetIp, HopNumber, HopIp, RttMs, Hostname, CreatedAt
                    FROM ReachabilityPathHops
                    WHERE TestId = @TestId
                    ORDER BY HopNumber ASC
                ";
                command.Parameters.AddWithValue("@TestId", testId);

                var results = new List<ReachabilityPathHopEntry>();
                using var reader = await command.ExecuteReaderAsync();
                while (await reader.ReadAsync())
                {
                    results.Add(new ReachabilityPathHopEntry
                    {
                        Id = reader.GetInt64(0),
                        TestId = reader.GetInt64(1),
                        TargetIp = reader.GetString(2),
                        HopNumber = reader.GetInt32(3),
                        HopIp = reader.IsDBNull(4) ? null : reader.GetString(4),
                        RttMs = reader.IsDBNull(5) ? null : (long?)reader.GetInt64(5),
                        Hostname = reader.IsDBNull(6) ? null : reader.GetString(6),
                        CreatedAt = DateTime.Parse(reader.GetString(7))
                    });
                }

                return results;
            }
            catch (Exception ex)
            {
                Logger.Error(ex, $"Failed to get path hops for test {testId}");
                throw;
            }
        }

        /// <summary>
        /// Get deeper scans for a specific test ID
        /// </summary>
        public async Task<List<ReachabilityDeeperScanEntry>> GetReachabilityDeeperScansAsync(long testId)
        {
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();

                var command = connection.CreateCommand();
                command.CommandText = @"
                    SELECT Id, TestId, TargetIp, PortStates, Summary, CreatedAt
                    FROM ReachabilityDeeperScans
                    WHERE TestId = @TestId
                    ORDER BY CreatedAt ASC
                ";
                command.Parameters.AddWithValue("@TestId", testId);

                var results = new List<ReachabilityDeeperScanEntry>();
                using var reader = await command.ExecuteReaderAsync();
                while (await reader.ReadAsync())
                {
                    results.Add(new ReachabilityDeeperScanEntry
                    {
                        Id = reader.GetInt64(0),
                        TestId = reader.GetInt64(1),
                        TargetIp = reader.GetString(2),
                        PortStates = reader.GetString(3),
                        Summary = reader.IsDBNull(4) ? null : reader.GetString(4),
                        CreatedAt = DateTime.Parse(reader.GetString(5))
                    });
                }

                return results;
            }
            catch (Exception ex)
            {
                Logger.Error(ex, $"Failed to get deeper scans for test {testId}");
                throw;
            }
        }

        /// <summary>
        /// Get SNMP walks for a specific test ID
        /// </summary>
        public async Task<List<ReachabilitySnmpWalkEntry>> GetReachabilitySnmpWalksAsync(long testId)
        {
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();

                var command = connection.CreateCommand();
                command.CommandText = @"
                    SELECT Id, TestId, TargetIp, Port, Success, SuccessfulCommunity, SuccessfulOids, Attempts, DurationMs, CreatedAt
                    FROM ReachabilitySnmpWalks
                    WHERE TestId = @TestId
                    ORDER BY CreatedAt ASC
                ";
                command.Parameters.AddWithValue("@TestId", testId);

                var results = new List<ReachabilitySnmpWalkEntry>();
                using var reader = await command.ExecuteReaderAsync();
                while (await reader.ReadAsync())
                {
                    results.Add(new ReachabilitySnmpWalkEntry
                    {
                        Id = reader.GetInt64(0),
                        TestId = reader.GetInt64(1),
                        TargetIp = reader.GetString(2),
                        Port = reader.GetInt32(3),
                        Success = reader.GetInt32(4) == 1,
                        SuccessfulCommunity = reader.IsDBNull(5) ? null : reader.GetString(5),
                        SuccessfulOids = reader.GetString(6),
                        Attempts = reader.GetInt32(7),
                        DurationMs = reader.GetInt64(8),
                        CreatedAt = DateTime.Parse(reader.GetString(9))
                    });
                }

                return results;
            }
            catch (Exception ex)
            {
                Logger.Error(ex, $"Failed to get SNMP walks for test {testId}");
                throw;
            }
        }

        /// <summary>
        /// Delete reachability tests (and cascade delete child records)
        /// </summary>
        public async Task DeleteReachabilityTestsAsync(IEnumerable<long> ids)
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
                    DELETE FROM ReachabilityTests
                    WHERE Id IN ({placeholders})
                ";

                for (int i = 0; i < idsList.Count; i++)
                {
                    command.Parameters.AddWithValue($"@Id{i}", idsList[i]);
                }

                await command.ExecuteNonQueryAsync();
                Logger.Info($"Deleted {idsList.Count} reachability test(s)");
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "Failed to delete reachability tests");
                throw;
            }
        }

        /// <summary>
        /// Mark reachability tests as synced
        /// </summary>
        public async Task MarkReachabilityTestsAsSyncedAsync(IEnumerable<long> ids, DateTime syncedAt)
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
                    UPDATE ReachabilityTests
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
                Logger.Error(ex, "Failed to mark reachability tests as synced");
                throw;
            }
        }

        private AttackLogEntry MapReaderToEntry(DbDataReader reader)
        {
            var entry = new AttackLogEntry
            {
                Id = reader.GetInt64(reader.GetOrdinal("Id")),
                ProjectName = reader.IsDBNull(reader.GetOrdinal("ProjectName")) ? null : reader.GetString(reader.GetOrdinal("ProjectName")),
                AttackType = reader.GetString(reader.GetOrdinal("AttackType")),
                Protocol = reader.GetString(reader.GetOrdinal("Protocol")),
                SourceIp = reader.GetString(reader.GetOrdinal("SourceIp")),
                SourceMac = reader.IsDBNull(reader.GetOrdinal("SourceMac")) ? null : reader.GetString(reader.GetOrdinal("SourceMac")),
                TargetIp = reader.GetString(reader.GetOrdinal("TargetIp")),
                TargetMac = reader.IsDBNull(reader.GetOrdinal("TargetMac")) ? null : reader.GetString(reader.GetOrdinal("TargetMac")),
                TargetPort = reader.GetInt32(reader.GetOrdinal("TargetPort")),
                TargetRateMbps = reader.GetDouble(reader.GetOrdinal("TargetRateMbps")),
                PacketsSent = reader.GetInt64(reader.GetOrdinal("PacketsSent")),
                DurationSeconds = reader.GetInt32(reader.GetOrdinal("DurationSeconds")),
                StartTime = DateTime.Parse(reader.GetString(reader.GetOrdinal("StartTime"))),
                StopTime = DateTime.Parse(reader.GetString(reader.GetOrdinal("StopTime"))),
                Note = reader.IsDBNull(reader.GetOrdinal("Note")) ? null : reader.GetString(reader.GetOrdinal("Note")),
                LogContent = reader.GetString(reader.GetOrdinal("LogContent")),
                CreatedAt = DateTime.Parse(reader.GetString(reader.GetOrdinal("CreatedAt"))),
                SyncedAt = reader.IsDBNull(reader.GetOrdinal("SyncedAt")) ? null : DateTime.Parse(reader.GetString(reader.GetOrdinal("SyncedAt"))),
                IsSynced = reader.GetInt32(reader.GetOrdinal("IsSynced")) == 1,
                Synced = reader.GetInt32(reader.GetOrdinal("IsSynced")) == 1
            };

            // Map metadata fields (may not exist in older databases)
            try
            {
                var hardwareIdOrdinal = reader.GetOrdinal("HardwareId");
                if (!reader.IsDBNull(hardwareIdOrdinal))
                    entry.HardwareId = reader.GetString(hardwareIdOrdinal);
            }
            catch { }

            try
            {
                var machineNameOrdinal = reader.GetOrdinal("MachineName");
                if (!reader.IsDBNull(machineNameOrdinal))
                    entry.MachineName = reader.GetString(machineNameOrdinal);
            }
            catch { }

            try
            {
                var usernameOrdinal = reader.GetOrdinal("Username");
                if (!reader.IsDBNull(usernameOrdinal))
                    entry.Username = reader.GetString(usernameOrdinal);
            }
            catch { }

            try
            {
                var userIdOrdinal = reader.GetOrdinal("UserId");
                if (!reader.IsDBNull(userIdOrdinal))
                {
                    var userIdStr = reader.GetString(userIdOrdinal);
                    if (Guid.TryParse(userIdStr, out var userId))
                        entry.UserId = userId;
                }
            }
            catch { }

            return entry;
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
                // SQLite connections are managed per-operation (using statements)
                // No persistent connections to close, but we can log disposal
                Logger.Debug("DatabaseService disposed");
            }

            _disposed = true;
        }
    }
}

