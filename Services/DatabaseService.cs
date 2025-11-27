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
    public class DatabaseService
    {
        private static readonly ILogger Logger = LogManager.GetCurrentClassLogger();
        private readonly string _dbPath;
        private readonly string _connectionString;

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
                        IsSynced INTEGER NOT NULL DEFAULT 0
                    );
                ";
                command.ExecuteNonQuery();
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
                     TargetRateMbps, PacketsSent, DurationSeconds, StartTime, StopTime, Note, LogContent, CreatedAt, IsSynced)
                    VALUES 
                    (@ProjectName, @AttackType, @Protocol, @SourceIp, @SourceMac, @TargetIp, @TargetMac, @TargetPort,
                     @TargetRateMbps, @PacketsSent, @DurationSeconds, @StartTime, @StopTime, @Note, @LogContent, @CreatedAt, 0);
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
                           CreatedAt, SyncedAt, IsSynced
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

        private AttackLogEntry MapReaderToEntry(DbDataReader reader)
        {
            return new AttackLogEntry
            {
                Id = reader.GetInt64(0),
                ProjectName = reader.IsDBNull(1) ? null : reader.GetString(1),
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
                SyncedAt = reader.IsDBNull(17) ? null : DateTime.Parse(reader.GetString(17)),
                IsSynced = reader.GetInt32(18) == 1,
                Synced = reader.GetInt32(18) == 1
            };
        }
    }
}

