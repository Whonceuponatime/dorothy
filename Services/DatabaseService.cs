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

            CheckAndRecreateDatabaseIfNeeded();

            InitializeDatabase();
        }

        private void CheckAndRecreateDatabaseIfNeeded()
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

                    CREATE TABLE IF NOT EXISTS reachability_runs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
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

                await EnsureMigrationsAsync(connection);

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

                var existingAssetId = await GetAssetIdByHostIpAsync(asset.HostIp);

                if (existingAssetId.HasValue)
                {

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

                    var updateCommand = connection.CreateCommand();
                    updateCommand.CommandText = @"
                        UPDATE Ports
                        SET Service = @Service, Banner = @Banner, ScanTime = @ScanTime, Synced = 0
                        WHERE Id = @Id
                    ";
                    updateCommand.Parameters.AddWithValue("@Id", Convert.ToInt64(existingPortId));
                    updateCommand.Parameters.AddWithValue("@Service", port.Service ?? (object)DBNull.Value);

                    var bannerValue = string.IsNullOrWhiteSpace(port.Banner) ? (object)DBNull.Value : port.Banner.Trim();
                    updateCommand.Parameters.AddWithValue("@Banner", bannerValue);
                    updateCommand.Parameters.AddWithValue("@ScanTime", port.ScanTime.ToString("O"));

                    await updateCommand.ExecuteNonQueryAsync();
                    Logger.Info($"Updated existing port {port.Port}/{port.Protocol} for {port.HostIp} (Banner: {(string.IsNullOrWhiteSpace(port.Banner) ? "None" : port.Banner.Substring(0, Math.Min(50, port.Banner.Length)) + "...")})");
                }
                else
                {

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

                if (port.AssetId > 0)
                {
                    await UpdateAssetPortsColumnAsync(port.AssetId, port.HostIp);
                }
                else if (!string.IsNullOrEmpty(port.HostIp))
                {

                    var assetId = await GetAssetIdByHostIpAsync(port.HostIp);
                    if (assetId.HasValue)
                    {
                        await UpdateAssetPortsColumnAsync(assetId.Value, port.HostIp);
                    }
                }

                if (markAssetUnsynced && port.AssetId > 0)
                {
                    await MarkAssetAsUnsyncedAsync(port.AssetId);
                }
                else if (markAssetUnsynced && !string.IsNullOrEmpty(port.HostIp))
                {

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

                await EnsureMigrationsAsync(connection);

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

                Logger.Debug("DatabaseService disposed");
            }

            _disposed = true;
        }
    }
}

