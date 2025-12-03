using System;
using System.Runtime.Serialization;
using System.Text.Json.Serialization;
using Supabase.Postgrest.Attributes;
using Supabase.Postgrest.Models;

namespace Dorothy.Models.Database
{
    [Table("releases")]
    public class ReleaseEntry : BaseModel
    {
        [PrimaryKey("id")]
        public long Id { get; set; }

        [Column("version")]
        public string Version { get; set; } = string.Empty;

        [Column("release_notes")]
        public string? ReleaseNotes { get; set; }

        [Column("installer_file_name")]
        public string InstallerFileName { get; set; } = string.Empty;

        [Column("installer_file_path")]
        public string InstallerFilePath { get; set; } = string.Empty;

        [Column("installer_file_size")]
        public long InstallerFileSize { get; set; }

        [Column("installer_mime_type")]
        public string InstallerMimeType { get; set; } = string.Empty;

        [Column("created_by")]
        public Guid? CreatedBy { get; set; }

        [Column("created_at")]
        public DateTime CreatedAt { get; set; }

        [Column("updated_at")]
        public DateTime UpdatedAt { get; set; }
    }
}
