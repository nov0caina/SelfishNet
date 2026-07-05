using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Threading;
using SharpPcap.LibPcap;
using System;
using System.Collections.ObjectModel;
using System.Linq;

namespace SelfishNet
{
    public partial class MainWindow : Window
    {
        private CArp _engine;
        public ObservableCollection<PC> DetectedPCs { get; set; }

        public MainWindow()
        {
            InitializeComponent();
            DetectedPCs = new ObservableCollection<PC>();

            var listBox = this.FindControl<ListBox>("PcListBox");
            listBox.ItemsSource = DetectedPCs;

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

        public void OnScanClick(object sender, RoutedEventArgs e)
        {
            var combo = this.FindControl<ComboBox>("NetInterfacesBox");
            var device = combo.SelectedItem as LibPcapLiveDevice;
            if (device == null)
            {
                SetStatus("⚠ Select a network interface first.", "#FF9800");
                return;
            }

            // If engine exists, stop previous operations and release resources
            if (_engine != null)
            {
                SetStatus("Stopping previous scan...", "#FF9800");
                _engine.StopArpListener();
                _engine.StopDiscovery();
                _engine.StopSpoofing();
                _engine.StopTrafficMonitor();
                _engine.Dispose();
                _engine = null;

                // Reset spoof button to initial state
                var btn = this.FindControl<Button>("BtnSpoof");
                btn.Content = "⚡ START ARP SPOOF";
                btn.Background = Avalonia.Media.SolidColorBrush.Parse("#CA3E47");
            }

            DetectedPCs.Clear();

            try
            {
                var deviceList = new PcList();
                deviceList.SetOnDeviceAdded((newPc) =>
                {
                    Dispatcher.UIThread.InvokeAsync(() =>
                    {
                        DetectedPCs.Add(newPc);
                        SetStatus($"🔍 {DetectedPCs.Count} device(s) detected on the network.", "#8BC34A");
                    });
                });

                _engine = new CArp(device, deviceList);

                // Show detected network info
                string localIp = _engine.LocalIp != null ? new System.Net.IPAddress(_engine.LocalIp).ToString() : "N/A";
                string routerIp = _engine.RouterIp != null ? new System.Net.IPAddress(_engine.RouterIp).ToString() : "N/A";
                string subnet = _engine.SubnetMask != null ? new System.Net.IPAddress(_engine.SubnetMask).ToString() : "/24 (fallback)";
                SetStatus($"Scanning... Local: {localIp} | Gateway: {routerIp} | Mask: {subnet}", "#29B6F6");

                _engine.StartArpListener();
                _engine.StartArpDiscovery();
                _engine.StartTrafficMonitor();
            }
            catch (Exception ex)
            {
                SetStatus($"❌ Error starting scan: {ex.Message}", "#F44336");
                Console.WriteLine($"[SCAN ERROR] {ex}");
            }
        }

        public void OnSpoofClick(object sender, RoutedEventArgs e)
        {
            if (_engine == null)
            {
                SetStatus("⚠ Scan the network before starting spoof.", "#FF9800");
                return;
            }

            var btn = this.FindControl<Button>("BtnSpoof");
            if (btn.Content.ToString().Contains("START"))
            {
                if (_engine.RouterMac == null)
                {
                    SetStatus("❌ Router MAC not detected. Scan again.", "#F44336");
                    return;
                }
                _engine.StartSpoofing();
                btn.Content = "⛔ STOP SPOOF";
                btn.Background = Avalonia.Media.SolidColorBrush.Parse("#444");
                SetStatus("⚡ ARP Spoof active — intercepting traffic.", "#F44336");
            }
            else
            {
                _engine.StopSpoofing();
                btn.Content = "⚡ START ARP SPOOF";
                btn.Background = Avalonia.Media.SolidColorBrush.Parse("#CA3E47");
                SetStatus("Spoof stopped. Network restored.", "#8BC34A");
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
                status.Text = message;
                status.Foreground = Avalonia.Media.SolidColorBrush.Parse(hexColor);
            }
            else
            {
                Dispatcher.UIThread.InvokeAsync(() => SetStatus(message, hexColor));
            }
        }

        protected override void OnClosed(EventArgs e)
        {
            _engine?.Dispose();
            _engine = null;
            base.OnClosed(e);
        }
    }
}