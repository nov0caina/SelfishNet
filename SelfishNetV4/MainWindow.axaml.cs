using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Threading;
using SharpPcap.LibPcap;
using System;
using System.Collections.ObjectModel;
using System.Linq;

namespace SelfishNetV4
{
    public partial class MainWindow : Window
    {
        private CArp engine;
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
            var devices = SharpPcap.CaptureDeviceList.Instance;
            var validDevices = devices.OfType<LibPcapLiveDevice>().Where(d => d.Addresses.Any(a =>
                a.Addr.ipAddress != null &&
                a.Addr.ipAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork));

            var combo = this.FindControl<ComboBox>("NetInterfacesBox");
            combo.ItemsSource = validDevices.ToList();
            combo.DisplayMemberBinding = new Avalonia.Data.Binding("Name");
            if (validDevices.Any()) combo.SelectedIndex = 0;
        }

        public void OnScanClick(object sender, RoutedEventArgs e)
        {
            var combo = this.FindControl<ComboBox>("NetInterfacesBox");
            var device = combo.SelectedItem as LibPcapLiveDevice;
            if (device == null) return;

            if (engine == null)
            {
                var logicalList = new PcList();

                logicalList.SetCallBackOnNewPC((newPc) =>
                {
                    Dispatcher.UIThread.InvokeAsync(() =>
                    {
                        DetectedPCs.Add(newPc);
                    });
                });

                engine = new CArp(device, logicalList);
            }

            DetectedPCs.Clear();
            engine.startArpListener();
            engine.startArpDiscovery();
        }

        public void OnSpoofClick(object sender, RoutedEventArgs e)
        {
            if (engine == null) return;

            var btn = this.FindControl<Button>("BtnSpoof");
            if (btn.Content.ToString().Contains("START"))
            {
                engine.StartSpoofing();
                btn.Content = "⛔ STOP SPOOF";
                btn.Background = Avalonia.Media.SolidColorBrush.Parse("#444");
            }
            else
            {
                engine.StopSpoofing();
                btn.Content = "⚡ START ARP SPOOF";
                btn.Background = Avalonia.Media.SolidColorBrush.Parse("#CA3E47");
            }
        }
    }
}