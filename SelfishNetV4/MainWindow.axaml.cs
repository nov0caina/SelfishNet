using Avalonia.Controls;
using Avalonia.Interactivity;
using SharpPcap;
using SharpPcap.LibPcap;
using System.Linq;

namespace SelfishNetV4
{
    public partial class MainWindow : Window
    {
        private CArp engine;

        public MainWindow()
        {
            InitializeComponent();
            LoadInterfaces();
        }

        private void LoadInterfaces()
        {
            var devices = CaptureDeviceList.Instance;

            var validDevices = devices.OfType<LibPcapLiveDevice>().Where(d => d.Addresses.Any(a =>
                a.Addr.ipAddress != null &&
                a.Addr.ipAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork));

            var combo = this.FindControl<ComboBox>("NetInterfacesBox");
            combo.ItemsSource = validDevices.ToList();

            combo.DisplayMemberBinding = new Avalonia.Data.Binding("Name");
        }

        public void OnScanClick(object sender, RoutedEventArgs e)
        {
            var combo = this.FindControl<ComboBox>("NetInterfacesBox");
            var device = combo.SelectedItem as LibPcapLiveDevice;

            if (device == null)
            {
                Console.WriteLine("¡Selecciona una interfaz primero!");
                return;
            }

            Console.WriteLine($"Usando interfaz: {device.Description}");

            if (engine == null)
            {
                engine = new CArp(device, new PcList());
            }

            engine.startArpListener();   // Escucha respuestas
            engine.startArpDiscovery();  // Envía preguntas (Who-Has)
        }

        public void OnSpoofClick(object sender, RoutedEventArgs e)
        {
            if (engine == null) return;
            engine.StartSpoofing();
        }
    }
}