using System;
using System.Collections.Generic;
using System.Data.Common;
using System.IO;
using System.Linq;
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
            InitializeDatabase();
        }

        private void MigrateDatabase(SqliteConnection connection)
        {
            try
            {
                // Check if Assets table needs migration (add metadata columns)
                var checkCommand = connection.CreateCommand();
                checkCommand.CommandText = "PRAGMA table_info(Assets)";
                
                var columns = new HashSet<string>();
                using (var reader = checkCommand.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        columns.Add(reader.GetString(1)); // Column name is at index 1
                    }
                }

                // Add missing columns to Assets table
                if (!columns.Contains("HardwareId"))
                {
                    Logger.Info("Migrating Assets table: Adding HardwareId column");
                    var addColumn = connection.CreateCommand();
                    addColumn.CommandText = "ALTER TABLE Assets ADD COLUMN HardwareId TEXT";
                    addColumn.ExecuteNonQuery();
                }

                if (!columns.Contains("MachineName"))
                {
                    Logger.Info("Migrating Assets table: Adding MachineName column");
                    var addColumn = connection.CreateCommand();
                    addColumn.CommandText = "ALTER TABLE Assets ADD COLUMN MachineName TEXT";
                    addColumn.ExecuteNonQuery();
                }

                if (!columns.Contains("Username"))
                {
                    Logger.Info("Migrating Assets table: Adding Username column");
                    var addColumn = connection.CreateCommand();
                    addColumn.CommandText = "ALTER TABLE Assets ADD COLUMN Username TEXT";
                    addColumn.ExecuteNonQuery();
                }

                if (!columns.Contains("UserId"))
                {
                    Logger.Info("Migrating Assets table: Adding UserId column");
                    var addColumn = connection.CreateCommand();
                    addColumn.CommandText = "ALTER TABLE Assets ADD COLUMN UserId TEXT";
                    addColumn.ExecuteNonQuery();
                }

                if (!columns.Contains("Ports"))
                {
                    Logger.Info("Migrating Assets table: Adding Ports column");
                    var addColumn = connection.CreateCommand();
                    addColumn.CommandText = "ALTER TABLE Assets ADD COLUMN Ports TEXT";
                    addColumn.ExecuteNonQuery();
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

        public async Task<long> SaveAttackLogAsync(AttackLogEntry entry)
        {
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();

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

                var command = connection.CreateCommand();
                string query = @"
                    SELECT Id, ProjectName, AttackType, Protocol, SourceIp, SourceMac, TargetIp, TargetMac, TargetPort,
                           TargetRateMbps, PacketsSent, DurationSeconds, StartTime, StopTime, Note, LogContent, 
                           CreatedAt, SyncedAt, IsSynced, HardwareId, MachineName, Username, UserId
                    FROM AttackLogs
                    WHERE IsSynced = 0";
                
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

                var command = connection.CreateCommand();
                command.CommandText = @"
                    SELECT Id, AssetId, HostIp, Port, Protocol, Service, Banner, ScanTime, ProjectName, 
                           CreatedAt, Synced, HardwareId, MachineName, Username, UserId
                    FROM Ports
                    WHERE HostIp = @HostIp
                    ORDER BY Port ASC
                ";

                command.Parameters.AddWithValue("@HostIp", hostIp);

                var ports = new List<PortEntry>();
                using (var reader = await command.ExecuteReaderAsync())
                {
                    while (await reader.ReadAsync())
                    {
                        ports.Add(new PortEntry
                        {
                            Id = reader.GetInt64(0),
                            AssetId = reader.IsDBNull(1) ? 0 : reader.GetInt64(1),
                            HostIp = reader.GetString(2),
                            Port = reader.GetInt32(3),
                            Protocol = reader.GetString(4),
                            Service = reader.IsDBNull(5) ? null : reader.GetString(5),
                            Banner = reader.IsDBNull(6) ? null : reader.GetString(6),
                            ScanTime = DateTime.Parse(reader.GetString(7)),
                            ProjectName = reader.IsDBNull(8) ? null : reader.GetString(8),
                            CreatedAt = DateTime.Parse(reader.GetString(9)),
                            Synced = reader.GetInt32(10) == 1,
                            HardwareId = reader.IsDBNull(11) ? null : reader.GetString(11),
                            MachineName = reader.IsDBNull(12) ? null : reader.GetString(12),
                            Username = reader.IsDBNull(13) ? null : reader.GetString(13),
                            UserId = reader.IsDBNull(14) ? null : (Guid.TryParse(reader.GetString(14), out var userId) ? userId : (Guid?)null)
                        });
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

                var command = connection.CreateCommand();
                command.CommandText = @"
                    SELECT Id, AssetId, HostIp, Port, Protocol, Service, Banner, ScanTime, ProjectName, 
                           CreatedAt, Synced, HardwareId, MachineName, Username, UserId
                    FROM Ports
                    WHERE HostIp = @HostIp AND Synced = 0
                    ORDER BY Port ASC
                ";

                command.Parameters.AddWithValue("@HostIp", hostIp);

                var ports = new List<PortEntry>();
                using (var reader = await command.ExecuteReaderAsync())
                {
                    while (await reader.ReadAsync())
                    {
                        ports.Add(new PortEntry
                        {
                            Id = reader.GetInt64(0),
                            AssetId = reader.IsDBNull(1) ? 0 : reader.GetInt64(1),
                            HostIp = reader.GetString(2),
                            Port = reader.GetInt32(3),
                            Protocol = reader.GetString(4),
                            Service = reader.IsDBNull(5) ? null : reader.GetString(5),
                            Banner = reader.IsDBNull(6) ? null : reader.GetString(6),
                            ScanTime = DateTime.Parse(reader.GetString(7)),
                            ProjectName = reader.IsDBNull(8) ? null : reader.GetString(8),
                            CreatedAt = DateTime.Parse(reader.GetString(9)),
                            Synced = reader.GetInt32(10) == 1,
                            HardwareId = reader.IsDBNull(11) ? null : reader.GetString(11),
                            MachineName = reader.IsDBNull(12) ? null : reader.GetString(12),
                            Username = reader.IsDBNull(13) ? null : reader.GetString(13),
                            UserId = reader.IsDBNull(14) ? null : (Guid.TryParse(reader.GetString(14), out var userId) ? userId : (Guid?)null)
                        });
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

                var command = connection.CreateCommand();
                string query = @"
                    SELECT Id, HostIp, HostName, MacAddress, Vendor, IsOnline, PingTime, ScanTime, ProjectName, Synced, CreatedAt, SyncedAt,
                           HardwareId, MachineName, Username, UserId, Ports
                    FROM Assets
                    WHERE Synced = 0";
                
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

