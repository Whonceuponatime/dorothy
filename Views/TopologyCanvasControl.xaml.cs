using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using Microsoft.Web.WebView2.Core;
using NLog;

namespace Dorothy.Views
{
    public partial class TopologyCanvasControl : UserControl
    {
        private static readonly ILogger Logger = LogManager.GetCurrentClassLogger();

        public event Action<string, string>? NodeClicked;
        public event Action<string>? SubnetExpandRequested;
        public event Action<string>? DeepProbeRequested;
        public event Action<string>? TracerouteRequested;
        public event Action<string>? SnmpWalkRequested;
        public event Action<string>? SetAsAttackTargetRequested;

        private string _pendingContextNodeId = string.Empty;
        private string _pendingContextNodeType = string.Empty;
        private string _pendingContextIp = string.Empty;
        private string _pendingContextSubnet = string.Empty;
        private bool _isInitialized;
        private string _pendingTheme = "Dark";
        private bool _hasReceivedInitialLayout;
        private string? _pendingElements;

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
            if (!_isInitialized || WebView.CoreWebView2 == null) return;
            if (string.IsNullOrWhiteSpace(cytoscapeJson)) cytoscapeJson = "{\"nodes\":[],\"edges\":[]}";
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
                Logger.Info("TopoCanvas: not initialized yet, queueing payload");
                _pendingElements = cytoscapeElementsJson;
                return;
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
            _pendingElements = null;
            if (!_isInitialized || WebView.CoreWebView2 == null) return;
            TryPostToWebView("{\"type\":\"clear\"}");
        }

        public void SelectNode(string id)
        {
            if (!_isInitialized || WebView.CoreWebView2 == null || string.IsNullOrWhiteSpace(id)) return;
            var escaped = JsonEncodedText.Encode(id).ToString();
            TryPostToWebView($"{{\"type\":\"select\",\"id\":\"{escaped}\"}}");
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

            Logger.Info(
                $"TopoCanvas NavigationCompleted, isSuccess={e.IsSuccess}, " +
                $"pendingElements={_pendingElements != null}");

            if (!_isInitialized) return;

            var themeMsg = $"{{\"type\":\"theme\",\"value\":\"{_pendingTheme}\"}}";
            WebView.CoreWebView2?.PostWebMessageAsString(themeMsg);

            if (_pendingElements != null)
            {
                var queued = _pendingElements;
                _pendingElements = null;
                UpsertElements(queued);
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

                            Dispatcher.InvokeAsync(() =>
                            {
                                bool isSubnet = string.Equals(_pendingContextNodeType, "SubnetCloud", StringComparison.OrdinalIgnoreCase);
                                CtxExpandSubnet.Visibility = isSubnet ? Visibility.Visible : Visibility.Collapsed;

                                bool hasIp = !string.IsNullOrWhiteSpace(_pendingContextIp);
                                CtxDeepProbe.IsEnabled = hasIp;
                                CtxTraceroute.IsEnabled = hasIp;
                                CtxSnmp.IsEnabled = hasIp;
                                CtxSetAsTarget.IsEnabled = hasIp;

                                NodeContextMenu.IsOpen = true;
                            });
                            break;
                        }
                    case "edgeClick":
                        break;
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

        private void CtxDeepProbe_Click(object sender, RoutedEventArgs e)
        {
            NodeContextMenu.IsOpen = false;
            if (!string.IsNullOrEmpty(_pendingContextIp))
                DeepProbeRequested?.Invoke(_pendingContextIp);
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
