using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using Dorothy.Models;
using Microsoft.Web.WebView2.Core;
using NLog;

namespace Dorothy.Views
{
    public partial class TopologyCanvasControl : UserControl
    {
        private static readonly ILogger Logger = LogManager.GetCurrentClassLogger();

        public event Action<string, string>? NodeClicked;
        public event Action<string>? SubnetExpandRequested;
        public event Action<string, ProbeLevel>? ProbeRequested;
        // Fired when 2+ probe-able nodes are selected and the user picks a tier.
        public event Action<List<string>, ProbeLevel>? BulkProbeRequested;
        // Fired after a Shift+drag box-select completes (debounced JS-side).
        public event Action<int>? BoxSelectionCompleted;
        public event Action<string>? TracerouteRequested;
        public event Action<string>? SnmpWalkRequested;
        public event Action<string>? SetAsAttackTargetRequested;

        private string _pendingContextNodeId = string.Empty;
        private string _pendingContextNodeType = string.Empty;
        private string _pendingContextIp = string.Empty;
        private string _pendingContextSubnet = string.Empty;
        // Probe-able IPs from the cytoscape multi-selection at right-click time.
        // When this has 2+ entries, the Simple/Advanced buttons fire bulk probes.
        private List<string> _pendingContextSelectedIps = new();
        private bool _isInitialized;
        private string _pendingTheme = "Dark";
        private bool _hasReceivedInitialLayout;
        // Buffers for payloads that arrive before WebView2 finishes
        // navigating. The original implementation stored a single string
        // and overwrote on each call — every burst of pre-init upserts
        // collapsed to the LAST one, which then hit cytoscape with no
        // companion nodes and threw "Can not create edge with nonexistant
        // source". Now we queue every payload in arrival order and replay
        // the entire queue from NavigationCompleted. Init payloads use a
        // separate single slot — multiple inits supersede each other
        // (the latest snapshot wins), but they always replay BEFORE any
        // queued upserts so the upserts have nodes to attach to.
        private readonly object _pendingLock = new object();
        private readonly List<string> _pendingElements = new List<string>();
        private string? _pendingInit;

        // Live-discovery batching: while a scan is in flight, the orchestrator
        // raises ScanStarted → MainWindow calls BeginBatch on the canvas.
        // Every UpsertElements arriving during the scan is buffered instead of
        // pushed to cytoscape. ScanCompleted → EndBatch → all buffered payloads
        // merge into one envelope, push to cytoscape in a single round-trip.
        // Why: cytoscape-cola re-runs layout on each cy.add() call; with 90+
        // hosts streaming in over a stealth-mode scan, the canvas seizured and
        // collapsed nodes to a single point. Batching defers the layout pass
        // to a single one-shot run after all elements are present.
        private bool _batching;
        private readonly List<string> _batchedUpserts = new List<string>();
        private readonly object _batchLock = new object();

        public TopologyCanvasControl()
        {
            InitializeComponent();
        }

        public async Task InitializeAsync()
        {
            try
            {
                CoreWebView2Environment? env = null;
                try
                {
                    var userDataFolder = System.IO.Path.Combine(
                        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                        "SEACURE(TOOL)",
                        "WebView2");

                    try { System.IO.Directory.CreateDirectory(userDataFolder); }
                    catch (Exception ex)
                    {
                        Logger.Warn(ex,
                            $"Could not create WebView2 user data folder at {userDataFolder} — falling back to default");
                    }

                    env = await CoreWebView2Environment
                        .CreateAsync(browserExecutableFolder: null, userDataFolder: userDataFolder, options: null)
                        .ConfigureAwait(true);

                    Logger.Info($"WebView2 environment created with user data folder: {userDataFolder}");
                }
                catch (Exception ex)
                {
                    Logger.Warn(ex, "CoreWebView2Environment.CreateAsync failed — using default environment");
                    env = null;
                }

                if (env != null)
                    await WebView.EnsureCoreWebView2Async(env).ConfigureAwait(true);
                else
                    await WebView.EnsureCoreWebView2Async().ConfigureAwait(true);

                try
                {
                    WebView.CoreWebView2.Settings.AreDevToolsEnabled = true;
                }
                catch (Exception ex)
                {
                    Logger.Debug(ex, "Failed to enable WebView2 DevTools");
                }

                var uri = new Uri("pack://application:,,,/Resources/topology.html", UriKind.Absolute);
                var resourceInfo = Application.GetResourceStream(uri);
                if (resourceInfo == null)
                {
                    Logger.Warn("topology.html resource not found — WebView2 canvas will remain blank.");
                    return;
                }

                string html;
                using (var reader = new StreamReader(resourceInfo.Stream))
                {
                    html = await reader.ReadToEndAsync().ConfigureAwait(true);
                }

                WebView.NavigateToString(html);
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "Failed to initialize TopologyCanvasControl WebView2");
            }
        }

        public void InitGraph(string cytoscapeJson)
        {
            if (string.IsNullOrWhiteSpace(cytoscapeJson)) cytoscapeJson = "{\"nodes\":[],\"edges\":[]}";

            if (!_isInitialized || WebView.CoreWebView2 == null)
            {
                // Buffer the init payload — single slot is intentional, the
                // most recent snapshot supersedes any prior pending init.
                // Replays in NavigationCompleted before any queued upserts.
                lock (_pendingLock) { _pendingInit = cytoscapeJson; }
                Logger.Info("TopoCanvas: not initialized yet, queueing InitGraph payload");
                return;
            }

            _hasReceivedInitialLayout = true;
            var msg = $"{{\"type\":\"init\",\"elements\":{cytoscapeJson}}}";
            TryPostToWebView(msg);
        }

        public void UpsertElements(string cytoscapeElementsJson)
        {
            Logger.Info(
                $"TopoCanvas.UpsertElements called, isInit={_isInitialized}, " +
                $"hasInitialLayout={_hasReceivedInitialLayout}, " +
                $"payloadLength={cytoscapeElementsJson?.Length ?? 0}");

            if (string.IsNullOrWhiteSpace(cytoscapeElementsJson)) return;

            if (!_isInitialized)
            {
                // Append — every payload survives until NavigationCompleted
                // replays the queue in order. The previous single-slot
                // overwrite dropped all but the last, which is the bug
                // described in d3 of the topology-disconnect recon.
                lock (_pendingLock) { _pendingElements.Add(cytoscapeElementsJson); }
                Logger.Info($"TopoCanvas: not initialized yet, queued payload ({_pendingElements.Count} pending)");
                return;
            }

            // Batching during a scan: append + return. EndBatch will merge
            // all buffered payloads and push them to cytoscape as one envelope.
            lock (_batchLock)
            {
                if (_batching)
                {
                    _batchedUpserts.Add(cytoscapeElementsJson);
                    return;
                }
            }

            // cytoscapeElementsJson may arrive in one of two shapes:
            //   A) already wrapped: [{ "data": { "id": ... } }]
            //   B) unwrapped data dicts: [{ "id": ... }]
            // Callers that serialize ToCytoscapeData() directly produce (B);
            // Cytoscape.js requires (A). Normalize here so both work.
            try
            {
                using var doc = JsonDocument.Parse(cytoscapeElementsJson);
                var root = doc.RootElement;
                if (root.ValueKind != JsonValueKind.Array) return;

                var wrapped = new List<Dictionary<string, object>>();
                foreach (var el in root.EnumerateArray())
                {
                    if (el.TryGetProperty("data", out _))
                    {
                        wrapped.Add(JsonSerializer
                            .Deserialize<Dictionary<string, object>>(el.GetRawText())!);
                    }
                    else
                    {
                        wrapped.Add(new Dictionary<string, object>
                        {
                            ["data"] = JsonSerializer
                                .Deserialize<Dictionary<string, object>>(el.GetRawText())!
                        });
                    }
                }

                var normalized = JsonSerializer.Serialize(wrapped);
                string msgType = _hasReceivedInitialLayout ? "upsert" : "init";
                _hasReceivedInitialLayout = true;
                var msg = $"{{\"type\":\"{msgType}\",\"elements\":{normalized}}}";

                Logger.Info($"TopoCanvas POST: {msgType} bytes={msg.Length}");
                Logger.Info(
                    "TopoCanvas final payload preview: " +
                    msg.Substring(0, Math.Min(500, msg.Length)));

                WebView.CoreWebView2?.PostWebMessageAsString(msg);
            }
            catch (Exception ex)
            {
                Logger.Warn(ex, "TopoCanvas.UpsertElements: malformed json skipped");
            }
        }

        public void SetStatus(string text)
        {
            if (!_isInitialized || WebView.CoreWebView2 == null) return;
            var escaped = JsonEncodedText.Encode(text ?? string.Empty).ToString();
            var msg = $"{{\"type\":\"status\",\"text\":\"{escaped}\"}}";
            TryPostToWebView(msg);
        }

        public void ClearGraph()
        {
            _hasReceivedInitialLayout = false;
            lock (_pendingLock)
            {
                _pendingElements.Clear();
                _pendingInit = null;
            }
            lock (_batchLock)
            {
                _batching = false;
                _batchedUpserts.Clear();
            }
            if (!_isInitialized || WebView.CoreWebView2 == null) return;
            TryPostToWebView("{\"type\":\"clear\"}");
        }

        /// <summary>
        /// Open a batch window. While open, every UpsertElements call buffers
        /// instead of pushing to cytoscape. EndBatch merges + flushes once.
        /// Idempotent — calling Begin twice without End is a no-op on the
        /// second call (the existing batch keeps accumulating).
        /// </summary>
        public void BeginBatch()
        {
            lock (_batchLock)
            {
                if (_batching) return;
                _batching = true;
                _batchedUpserts.Clear();
            }
            Logger.Info("[TOPOLOGY] BeginBatch — live upserts will be buffered until EndBatch");
        }

        /// <summary>
        /// Close the batch window and flush all buffered payloads to cytoscape
        /// as one envelope. Cytoscape's handleUpsert performs the cy.add calls
        /// in one tick and runs cola layout exactly once for the full graph,
        /// instead of re-running it after every per-host arrival.
        /// </summary>
        public void EndBatch()
        {
            List<string> toFlush;
            lock (_batchLock)
            {
                if (!_batching) return;
                _batching = false;
                toFlush = new List<string>(_batchedUpserts);
                _batchedUpserts.Clear();
            }

            Logger.Info($"[TOPOLOGY] EndBatch — flushing {toFlush.Count} payloads to canvas");
            if (toFlush.Count == 0) return;

            string merged;
            try { merged = MergeBatchedPayloads(toFlush); }
            catch (Exception ex)
            {
                Logger.Warn(ex, "[TOPOLOGY] EndBatch merge failed; pushing payloads individually");
                foreach (var p in toFlush) UpsertElements(p);
                return;
            }

            if (!string.IsNullOrEmpty(merged)) UpsertElements(merged);
        }

        private static string MergeBatchedPayloads(List<string> payloads)
        {
            // Each payload is a JSON array of element data dicts (or wrapped
            // {data:{…}} dicts). Concatenate all elements into one big array
            // so a single handleUpsert call processes them; cola then re-runs
            // layout exactly once.
            var sb = new System.Text.StringBuilder();
            sb.Append('[');
            bool first = true;
            foreach (var p in payloads)
            {
                if (string.IsNullOrWhiteSpace(p)) continue;
                using var doc = JsonDocument.Parse(p);
                if (doc.RootElement.ValueKind != JsonValueKind.Array) continue;
                foreach (var el in doc.RootElement.EnumerateArray())
                {
                    if (!first) sb.Append(',');
                    sb.Append(el.GetRawText());
                    first = false;
                }
            }
            sb.Append(']');
            return sb.ToString();
        }

        public void SelectNode(string id)
        {
            if (!_isInitialized || WebView.CoreWebView2 == null || string.IsNullOrWhiteSpace(id)) return;
            var escaped = JsonEncodedText.Encode(id).ToString();
            TryPostToWebView($"{{\"type\":\"select\",\"id\":\"{escaped}\"}}");
        }

        // Re-center the topology in the viewport. Used by the NI tab's
        // "↻ Center" button when nodes have been zoomed/panned out of frame.
        public void Recenter()
        {
            if (!_isInitialized || WebView.CoreWebView2 == null) return;
            TryPostToWebView("{\"type\":\"recenter\"}");
        }

        public void SetTheme(string themeName)
        {
            _pendingTheme = themeName;
            if (!_isInitialized) return;
            var msg = $"{{\"type\":\"theme\",\"value\":\"{themeName}\"}}";
            WebView.CoreWebView2?.PostWebMessageAsString(msg);
        }

        private void TryPostToWebView(string message)
        {
            try
            {
                WebView.CoreWebView2?.PostWebMessageAsString(message);
            }
            catch (Exception ex)
            {
                Logger.Debug(ex, "PostWebMessageAsString failed");
            }
        }

        private void WebView_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.F12)
            {
                try
                {
                    WebView.CoreWebView2?.OpenDevToolsWindow();
                    e.Handled = true;
                }
                catch (Exception ex)
                {
                    Logger.Debug(ex, "OpenDevToolsWindow failed");
                }
            }
        }

        private void WebView_NavigationCompleted(object? sender, CoreWebView2NavigationCompletedEventArgs e)
        {
            _isInitialized = e.IsSuccess;

            string? queuedInit;
            List<string> queuedUpserts;
            lock (_pendingLock)
            {
                queuedInit = _pendingInit;
                queuedUpserts = new List<string>(_pendingElements);
                _pendingInit = null;
                _pendingElements.Clear();
            }

            Logger.Info(
                $"TopoCanvas NavigationCompleted, isSuccess={e.IsSuccess}, " +
                $"pendingInit={queuedInit != null}, pendingUpserts={queuedUpserts.Count}");

            if (!_isInitialized) return;

            var themeMsg = $"{{\"type\":\"theme\",\"value\":\"{_pendingTheme}\"}}";
            WebView.CoreWebView2?.PostWebMessageAsString(themeMsg);

            // Init payload first — must arrive before any upserts so the
            // upserts have nodes to attach edges to. Single slot was already
            // last-write-wins so the most recent snapshot is correct.
            if (queuedInit != null)
            {
                InitGraph(queuedInit);
            }

            // Replay every queued upsert in arrival order. The orchestrator
            // emits NodeChanged before EdgeChanged for any single discovery
            // event; preserving order means edges still find their endpoints.
            foreach (var pending in queuedUpserts)
            {
                UpsertElements(pending);
            }
        }

        private void WebView_WebMessageReceived(object? sender, CoreWebView2WebMessageReceivedEventArgs e)
        {
            string? json = null;
            try { json = e.TryGetWebMessageAsString(); } catch { json = null; }
            if (string.IsNullOrWhiteSpace(json)) return;

            Logger.Info($"TopoCanvas RECV from JS: {json}");

            try
            {
                using var doc = JsonDocument.Parse(json);
                var root = doc.RootElement;
                if (!root.TryGetProperty("event", out var evtElement)) return;
                var evt = evtElement.GetString();

                switch (evt)
                {
                    case "nodeClick":
                        {
                            var id = TryGetString(root, "id");
                            var type = TryGetString(root, "type");
                            NodeClicked?.Invoke(id, type);
                            break;
                        }
                    case "nodeRightClick":
                        {
                            _pendingContextNodeId = TryGetString(root, "id");
                            _pendingContextNodeType = TryGetString(root, "type");
                            _pendingContextIp = TryGetString(root, "ip");
                            _pendingContextSubnet = TryGetString(root, "subnet");

                            _pendingContextSelectedIps = new List<string>();
                            int reportedJsCount = -1;
                            if (root.TryGetProperty("selectedIps", out var selEl)
                                && selEl.ValueKind == JsonValueKind.Array)
                            {
                                foreach (var item in selEl.EnumerateArray())
                                {
                                    if (item.ValueKind != JsonValueKind.String) continue;
                                    var ip = item.GetString();
                                    if (!string.IsNullOrWhiteSpace(ip))
                                        _pendingContextSelectedIps.Add(ip!);
                                }
                            }
                            if (root.TryGetProperty("selectedIpsCount", out var cEl)
                                && cEl.ValueKind == JsonValueKind.Number)
                            {
                                reportedJsCount = cEl.GetInt32();
                            }
                            Logger.Info(
                                $"[BULK PROBE] nodeRightClick parsed {_pendingContextSelectedIps.Count} " +
                                $"selectedIps from JS" +
                                (reportedJsCount >= 0 ? $" (JS reported count={reportedJsCount})" : ""));
                            if (reportedJsCount >= 0
                                && reportedJsCount != _pendingContextSelectedIps.Count)
                            {
                                Logger.Warn(
                                    $"[BULK PROBE] MISMATCH: JS sent {reportedJsCount} IPs but " +
                                    $"C# parsed {_pendingContextSelectedIps.Count}");
                            }

                            Dispatcher.InvokeAsync(() =>
                            {
                                bool isSubnet = string.Equals(_pendingContextNodeType, "SubnetCloud", StringComparison.OrdinalIgnoreCase);
                                CtxExpandSubnet.Visibility = isSubnet ? Visibility.Visible : Visibility.Collapsed;

                                bool hasIp = !string.IsNullOrWhiteSpace(_pendingContextIp);
                                int selCount = _pendingContextSelectedIps.Count;

                                // 2+ selected → buttons enter bulk mode and show the count.
                                if (selCount > 1)
                                {
                                    CtxSurveyProbe.Content   = $"Reachability test selected ({selCount})";
                                    CtxSimpleProbe.Content   = $"Banner grab selected ({selCount})";
                                    CtxAdvancedProbe.Content = $"Deep scan selected ({selCount})";
                                    CtxSurveyProbe.IsEnabled   = true;
                                    CtxSimpleProbe.IsEnabled   = true;
                                    CtxAdvancedProbe.IsEnabled = true;
                                }
                                else
                                {
                                    CtxSurveyProbe.Content   = "Reachability test (safe)";
                                    CtxSimpleProbe.Content   = "Banner grab (~15s)";
                                    CtxAdvancedProbe.Content = "Deep scan (~3min)";
                                    CtxSurveyProbe.IsEnabled   = hasIp;
                                    CtxSimpleProbe.IsEnabled   = hasIp;
                                    CtxAdvancedProbe.IsEnabled = hasIp;
                                }

                                CtxTraceroute.IsEnabled = hasIp;
                                CtxSnmp.IsEnabled = hasIp;
                                CtxSetAsTarget.IsEnabled = hasIp;

                                NodeContextMenu.IsOpen = true;
                            });
                            break;
                        }
                    case "edgeClick":
                        break;
                    case "boxSelectComplete":
                        {
                            int count = 0;
                            if (root.TryGetProperty("count", out var cEl)
                                && cEl.ValueKind == JsonValueKind.Number)
                            {
                                count = cEl.GetInt32();
                            }
                            BoxSelectionCompleted?.Invoke(count);
                            break;
                        }
                    case "ready":
                        break;
                    case "log":
                        {
                            var tag = root.TryGetProperty("tag", out var t)
                                ? (t.GetString() ?? "")
                                : "";
                            var data = root.TryGetProperty("data", out var d)
                                ? d.GetRawText()
                                : "{}";
                            Logger.Info($"TopoCanvas JS log [{tag}]: {data}");
                            break;
                        }
                }
            }
            catch (Exception ex)
            {
                Logger.Debug(ex, "WebView message parse failed");
            }
        }

        private static string TryGetString(JsonElement root, string name)
        {
            if (!root.TryGetProperty(name, out var el)) return string.Empty;
            return el.ValueKind switch
            {
                JsonValueKind.String => el.GetString() ?? string.Empty,
                JsonValueKind.Number => el.ToString(),
                JsonValueKind.True => "true",
                JsonValueKind.False => "false",
                _ => string.Empty
            };
        }

        private void CtxExpandSubnet_Click(object sender, RoutedEventArgs e)
        {
            NodeContextMenu.IsOpen = false;
            if (!string.IsNullOrEmpty(_pendingContextSubnet))
                SubnetExpandRequested?.Invoke(_pendingContextSubnet);
        }

        private void CtxSurveyProbe_Click(object sender, RoutedEventArgs e)
        {
            NodeContextMenu.IsOpen = false;
            DispatchProbeFromContext(ProbeLevel.Survey);
        }

        private void CtxSimpleProbe_Click(object sender, RoutedEventArgs e)
        {
            NodeContextMenu.IsOpen = false;
            DispatchProbeFromContext(ProbeLevel.Simple);
        }

        private void CtxAdvancedProbe_Click(object sender, RoutedEventArgs e)
        {
            NodeContextMenu.IsOpen = false;
            DispatchProbeFromContext(ProbeLevel.Advanced);
        }

        private void DispatchProbeFromContext(ProbeLevel level)
        {
            if (_pendingContextSelectedIps.Count > 1)
            {
                BulkProbeRequested?.Invoke(_pendingContextSelectedIps, level);
                return;
            }
            if (!string.IsNullOrEmpty(_pendingContextIp))
                ProbeRequested?.Invoke(_pendingContextIp, level);
        }

        private void CtxTraceroute_Click(object sender, RoutedEventArgs e)
        {
            NodeContextMenu.IsOpen = false;
            if (!string.IsNullOrEmpty(_pendingContextIp))
                TracerouteRequested?.Invoke(_pendingContextIp);
        }

        private void CtxSnmp_Click(object sender, RoutedEventArgs e)
        {
            NodeContextMenu.IsOpen = false;
            if (!string.IsNullOrEmpty(_pendingContextIp))
                SnmpWalkRequested?.Invoke(_pendingContextIp);
        }

        private void CtxSetAsTarget_Click(object sender, RoutedEventArgs e)
        {
            NodeContextMenu.IsOpen = false;
            if (!string.IsNullOrEmpty(_pendingContextIp))
                SetAsAttackTargetRequested?.Invoke(_pendingContextIp);
        }
    }
}
