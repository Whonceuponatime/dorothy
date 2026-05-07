using System;

namespace Dorothy.Services
{
    /// <summary>
    /// Thin event hub for "scan activity has changed". Replaces the prior
    /// session/in-memory-flag model: with offline persistence, the DB is the
    /// source of truth (any row with EngagementId IS NULL is unsubmitted), and
    /// MainWindow refreshes its Submit-button state by querying the DB. This
    /// hub just signals "something changed, time to re-query."
    /// </summary>
    public static class EngagementContext
    {
        public static event EventHandler? ActivityChanged;

        /// <summary>
        /// Fire after any insert/update/delete that affects the unsubmitted
        /// bucket: scan saves, probe completions, attack-log saves, topology
        /// upserts, settings "Clear all local data".
        /// </summary>
        public static void NotifyActivityChanged()
        {
            try { ActivityChanged?.Invoke(null, EventArgs.Empty); }
            catch { /* listener errors must not corrupt state */ }
        }
    }
}
