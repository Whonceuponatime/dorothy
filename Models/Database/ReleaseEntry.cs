using System;

namespace Dorothy.Models.Database
{
    public class ReleaseEntry
    {
        public long Id { get; set; }
        public string Version { get; set; } = string.Empty;
        public string? ReleaseNotes { get; set; }
        public string InstallerFileName { get; set; } = string.Empty;
        public string InstallerFilePath { get; set; } = string.Empty;
        public long InstallerFileSize { get; set; }
        public string InstallerMimeType { get; set; } = string.Empty;
        public Guid? CreatedBy { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime UpdatedAt { get; set; }
    }
}
