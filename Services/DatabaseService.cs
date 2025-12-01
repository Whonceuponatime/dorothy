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
                        UserId TEXT
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

        public async Task<long> SaveAssetAsync(AssetEntry asset)
        {
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();

                var command = connection.CreateCommand();
                command.CommandText = @"
                    INSERT INTO Assets 
                    (HostIp, HostName, MacAddress, Vendor, IsOnline, PingTime, ScanTime, ProjectName, CreatedAt, Synced,
                     HardwareId, MachineName, Username, UserId)
                    VALUES 
                    (@HostIp, @HostName, @MacAddress, @Vendor, @IsOnline, @PingTime, @ScanTime, @ProjectName, @CreatedAt, 0,
                     @HardwareId, @MachineName, @Username, @UserId);
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

                var result = await command.ExecuteScalarAsync();
                return Convert.ToInt64(result);
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "Failed to save asset");
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
                           HardwareId, MachineName, Username, UserId
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
                UserId = reader.IsDBNull(15) ? null : Guid.Parse(reader.GetString(15))
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

