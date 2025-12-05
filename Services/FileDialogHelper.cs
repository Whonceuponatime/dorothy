using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Avalonia.Controls;
using Avalonia.Platform.Storage;

namespace Dorothy.Services
{
    /// <summary>
    /// Cross-platform file and folder dialog helper for Avalonia.
    /// </summary>
    public static class FileDialogHelper
    {
        /// <summary>
        /// Shows a folder browser dialog (cross-platform).
        /// </summary>
        public static async Task<string?> ShowFolderDialogAsync(Window parent, string? initialPath = null)
        {
            try
            {
                var storageProvider = parent.StorageProvider;
                var folderPicker = new FolderPickerOpenOptions
                {
                    Title = "Select Folder",
                    SuggestedStartLocation = !string.IsNullOrEmpty(initialPath) && Directory.Exists(initialPath)
                        ? await storageProvider.TryGetFolderFromPathAsync(initialPath)
                        : null
                };

                var result = await storageProvider.OpenFolderPickerAsync(folderPicker);
                if (result.Count > 0 && result[0] != null)
                {
                    return result[0].Path.LocalPath;
                }
            }
            catch (Exception)
            {
                // Fallback to manual path entry or return null
            }

            return null;
        }

        /// <summary>
        /// Shows a save file dialog (cross-platform).
        /// </summary>
        public static async Task<string?> ShowSaveFileDialogAsync(
            Window parent,
            string title,
            string? defaultFileName = null,
            string? defaultExtension = null,
            (string Name, string[] Extensions)[]? filters = null)
        {
            try
            {
                var storageProvider = parent.StorageProvider;
                var filePicker = new FilePickerSaveOptions
                {
                    Title = title,
                    SuggestedFileName = defaultFileName,
                    DefaultExtension = defaultExtension,
                    ShowOverwritePrompt = true
                };

                if (filters != null && filters.Length > 0)
                {
                    filePicker.FileTypeChoices = filters.Select(f => 
                        new FilePickerFileType(f.Name) { Patterns = f.Extensions }).ToArray();
                }

                var result = await storageProvider.SaveFilePickerAsync(filePicker);
                if (result != null)
                {
                    return result.Path.LocalPath;
                }
            }
            catch (Exception)
            {
                // Fallback or return null
            }

            return null;
        }

        /// <summary>
        /// Shows an open file dialog (cross-platform).
        /// </summary>
        public static async Task<string?> ShowOpenFileDialogAsync(
            Window parent,
            string title,
            (string Name, string[] Extensions)[]? filters = null,
            string? initialPath = null)
        {
            try
            {
                var storageProvider = parent.StorageProvider;
                var filePicker = new FilePickerOpenOptions
                {
                    Title = title,
                    AllowMultiple = false
                };

                if (filters != null && filters.Length > 0)
                {
                    filePicker.FileTypeFilter = filters.Select(f => 
                        new FilePickerFileType(f.Name) { Patterns = f.Extensions }).ToArray();
                }

                if (!string.IsNullOrEmpty(initialPath) && Directory.Exists(initialPath))
                {
                    filePicker.SuggestedStartLocation = await storageProvider.TryGetFolderFromPathAsync(initialPath);
                }

                var result = await storageProvider.OpenFilePickerAsync(filePicker);
                if (result.Count > 0 && result[0] != null)
                {
                    return result[0].Path.LocalPath;
                }
            }
            catch (Exception)
            {
                // Fallback or return null
            }

            return null;
        }
    }
}

