using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Threading;
using SharpPcap.LibPcap;
using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;

namespace SelfishNet
{
    public partial class MainWindow : Window
    {
        private CArp _engine;
        private IDeviceIdentifierService _identifierService;
        public ObservableCollection<PC> DetectedPCs { get; set; }

        public MainWindow()
        {
            InitializeComponent();
            DetectedPCs = new ObservableCollection<PC>();

            var listBox = this.FindControl<ListBox>("PcListBox");
            listBox.ItemsSource = DetectedPCs;

            AppDomain.CurrentDomain.ProcessExit += (s, e) => Cleanup();

            LoadInterfaces();
        }

        private void LoadInterfaces()
        {
            try
            {
                var devices = SharpPcap.CaptureDeviceList.Instance;
                var validDevices = devices.OfType<LibPcapLiveDevice>().Where(d => d.Addresses.Any(a =>
                    a.Addr.ipAddress != null &&
                    a.Addr.ipAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)).ToList();

                var combo = this.FindControl<ComboBox>("NetInterfacesBox");
                combo.ItemsSource = validDevices;
                combo.DisplayMemberBinding = new Avalonia.Data.Binding("Name");

                if (validDevices.Any())
                {
                    combo.SelectedIndex = 0;
                    SetStatus($"{validDevices.Count} interface(s) detected.", "#8BC34A");
                }
                else
                {
                    SetStatus("⚠ No valid network interfaces detected.", "#FF9800");
                }
            }
            catch (Exception ex)
            {
                SetStatus($"❌ Error loading interfaces: {ex.Message}", "#F44336");
            }
        }

        public async void OnScanClick(object sender, RoutedEventArgs e)
        {
            var combo = this.FindControl<ComboBox>("NetInterfacesBox");
            var device = combo.SelectedItem as LibPcapLiveDevice;
            if (device == null)
            {
                SetStatus("⚠ Select a network interface first.", "#FF9800");
                return;
            }

            var btnScan = this.FindControl<Button>("BtnScan");
            var btnSpoof = this.FindControl<Button>("BtnSpoof");
            if (btnScan != null) btnScan.IsEnabled = false;
            if (btnSpoof != null) btnSpoof.IsEnabled = false;

            // If engine exists, stop previous operations asynchronously
            if (_engine != null || _identifierService != null)
            {
                SetStatus("Stopping previous scan and releasing network resources...", "#FF9800");
                var oldEngine = _engine;
                var oldIdService = _identifierService;
                _engine = null;
                _identifierService = null;

                await Task.Run(() =>
                {
                    try
                    {
                        oldIdService?.StopMdnsListener();
                        oldIdService?.Dispose();
                        oldEngine?.StopArpListener();
                        oldEngine?.StopDiscovery();
                        oldEngine?.StopSpoofing();
                        oldEngine?.StopTrafficMonitor();
                        oldEngine?.Dispose();
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"[CLEANUP ERROR] {ex.Message}");
                    }
                });

                if (btnSpoof != null)
                {
                    btnSpoof.Content = "⚡ START ARP SPOOF";
                    btnSpoof.Background = Avalonia.Media.SolidColorBrush.Parse("#CA3E47");
                }
            }

            DetectedPCs.Clear();

            try
            {
                SetStatus("Initializing network scan...", "#29B6F6");

                var deviceList = new PcList();
                deviceList.SetOnDeviceAdded((newPc) =>
                {
                    Dispatcher.UIThread.InvokeAsync(() =>
                    {
                        DetectedPCs.Add(newPc);
                        SetStatus($"🔍 {DetectedPCs.Count} device(s) detected on the network.", "#8BC34A");
                    });
                });

                CArp newEngine = null;
                IDeviceIdentifierService newIdService = null;

                await Task.Run(() =>
                {
                    newEngine = new CArp(device, deviceList);
                    newIdService = new DeviceIdentifierService(device, deviceList);
                    deviceList.SetIdentifierService(newIdService);

                    newEngine.StartArpListener();
                    newEngine.StartArpDiscovery();
                    newEngine.StartTrafficMonitor();
                    newIdService.StartMdnsListener();
                });

                _engine = newEngine;
                _identifierService = newIdService;

                // Show detected network info
                string localIp = _engine.LocalIp != null ? new System.Net.IPAddress(_engine.LocalIp).ToString() : "N/A";
                string routerIp = _engine.RouterIp != null ? new System.Net.IPAddress(_engine.RouterIp).ToString() : "N/A";
                string subnet = _engine.SubnetMask != null ? new System.Net.IPAddress(_engine.SubnetMask).ToString() : "/24 (fallback)";
                SetStatus($"Scanning... Local: {localIp} | Gateway: {routerIp} | Mask: {subnet}", "#29B6F6");
            }
            catch (Exception ex)
            {
                SetStatus($"❌ Error starting scan: {ex.Message}", "#F44336");
                Console.WriteLine($"[SCAN ERROR] {ex}");
            }
            finally
            {
                if (btnScan != null) btnScan.IsEnabled = true;
                if (btnSpoof != null) btnSpoof.IsEnabled = true;
            }
        }

        public async void OnSpoofClick(object sender, RoutedEventArgs e)
        {
            if (_engine == null)
            {
                SetStatus("⚠ Scan the network before starting spoof.", "#FF9800");
                return;
            }

            var btn = this.FindControl<Button>("BtnSpoof");
            if (btn == null) return;
            btn.IsEnabled = false;

            try
            {
                if (btn.Content.ToString().Contains("START"))
                {
                    if (_engine.RouterMac == null)
                    {
                        SetStatus("❌ Router MAC not detected. Scan again.", "#F44336");
                        return;
                    }

                    await Task.Run(() => _engine.StartSpoofing());
                    btn.Content = "⛔ STOP SPOOF";
                    btn.Background = Avalonia.Media.SolidColorBrush.Parse("#444");
                    SetStatus("⚡ ARP Spoof active — intercepting traffic.", "#F44336");
                }
                else
                {
                    SetStatus("Stopping spoof and restoring network tables...", "#FF9800");
                    await Task.Run(() => _engine.StopSpoofing());
                    btn.Content = "⚡ START ARP SPOOF";
                    btn.Background = Avalonia.Media.SolidColorBrush.Parse("#CA3E47");
                    SetStatus("Spoof stopped. Network restored.", "#8BC34A");
                }
            }
            finally
            {
                btn.IsEnabled = true;
            }
        }

        /// <summary>
        /// Updates the status bar with a message and color.
        /// Thread-safe: can be called from any thread.
        /// </summary>
        private void SetStatus(string message, string hexColor = "#888")
        {
            if (Dispatcher.UIThread.CheckAccess())
            {
                var status = this.FindControl<TextBlock>("StatusText");
                if (status != null)
                {
                    status.Text = message;
                    status.Foreground = Avalonia.Media.SolidColorBrush.Parse(hexColor);
                }
            }
            else
            {
                Dispatcher.UIThread.InvokeAsync(() => SetStatus(message, hexColor));
            }
        }

        private void Cleanup()
        {
            try
            {
                _identifierService?.StopMdnsListener();
                _identifierService?.Dispose();
                _identifierService = null;
                _engine?.Dispose();
                _engine = null;
            }
            catch { }
        }

        protected override void OnClosed(EventArgs e)
        {
            Cleanup();
            base.OnClosed(e);
        }
    }
}