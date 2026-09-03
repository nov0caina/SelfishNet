using System;
using System.ComponentModel;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.CompilerServices;

namespace SelfishNet
{
    public class PC : INotifyPropertyChanged
    {
        // ── Display properties (XAML bindings) ──

        public string IpDisplay => Ip?.ToString() ?? "...";
        public string MacDisplay => Mac?.ToString() ?? "...";

        // ── Core network properties ──

        public IPAddress Ip { get; set; }
        public PhysicalAddress Mac { get; set; }
        public string Name { get; set; } = "Unknown";

        // ── Device identification ──

        private string _vendor;
        public string Vendor
        {
            get => _vendor;
            set { if (_vendor != value) { _vendor = value; OnPropertyChanged(); OnPropertyChanged(nameof(DeviceLabel)); } }
        }

        private string _hostname;
        public string Hostname
        {
            get => _hostname;
            set { if (_hostname != value) { _hostname = value; OnPropertyChanged(); OnPropertyChanged(nameof(DeviceLabel)); } }
        }

        private DeviceType _deviceCategory = DeviceType.Unknown;
        public DeviceType DeviceCategory
        {
            get => _deviceCategory;
            set { if (_deviceCategory != value) { _deviceCategory = value; OnPropertyChanged(); OnPropertyChanged(nameof(DeviceLabel)); } }
        }

        /// <summary>
        /// Computed display label for UI: combines device type, vendor, and hostname.
        /// Falls back to formatted MAC address when no identification is available.
        /// </summary>
        public string DeviceLabel
        {
            get
            {
                string type = _deviceCategory != DeviceType.Unknown ? _deviceCategory.ToString() : null;
                string name = !string.IsNullOrEmpty(_hostname) ? _hostname : null;
                // Treat "Randomized MAC" as no vendor for label purposes
                bool isRandomized = string.Equals(_vendor, "Randomized MAC", StringComparison.Ordinal);
                string vendor = !string.IsNullOrEmpty(_vendor) && !isRandomized ? _vendor : null;

                if (type != null && name != null) return $"{type} — {name}";
                if (type != null && vendor != null) return $"{type} ({vendor})";
                if (name != null) return name;
                if (vendor != null) return vendor;

                // Fallback: show formatted MAC so user can distinguish devices
                if (Mac != null)
                {
                    string macStr = Mac.ToString();
                    // Format: "A23BC1D4E5F6" → "A2:3B:C1:D4:E5:F6"
                    if (macStr.Length == 12)
                    {
                        string label = isRandomized ? "📱 " : "";
                        return $"{label}{macStr[0..2]}:{macStr[2..4]}:{macStr[4..6]}:{macStr[6..8]}:{macStr[8..10]}:{macStr[10..12]}";
                    }
                }
                return "Unknown";
            }
        }

        private bool _redirect = false;
        public bool Redirect
        {
            get => _redirect;
            set
            {
                if (CanControl && _redirect != value)
                {
                    _redirect = value;
                    OnPropertyChanged();
                    OnPropertyChanged(nameof(IsThrottlingEnabled));
                    if (_redirect && _block)
                    {
                        _block = false;
                        OnPropertyChanged(nameof(Block));
                    }
                }
            }
        }

        private bool _block = false;
        public bool Block
        {
            get => _block;
            set
            {
                if (CanControl && _block != value)
                {
                    _block = value;
                    OnPropertyChanged();
                    if (_block && _redirect)
                    {
                        _redirect = false;
                        OnPropertyChanged(nameof(Redirect));
                        OnPropertyChanged(nameof(IsThrottlingEnabled));
                    }
                }
            }
        }

        private int _bandwidthLimitKb = 0;
        /// <summary>Allowed bandwidth limit in KB/s (0 = Unlimited).</summary>
        public int BandwidthLimitKb
        {
            get => _bandwidthLimitKb;
            set
            {
                int clamped = Math.Max(0, value);
                if (_bandwidthLimitKb != clamped)
                {
                    _bandwidthLimitKb = clamped;
                    OnPropertyChanged();
                    OnPropertyChanged(nameof(BandwidthLimitDisplay));
                }
            }
        }

        public string BandwidthLimitDisplay => _bandwidthLimitKb == 0 ? "Unlimited" : $"{_bandwidthLimitKb} KB/s";

        private bool _isGateway;
        public bool IsGateway
        {
            get => _isGateway;
            set
            {
                if (_isGateway != value)
                {
                    _isGateway = value;
                    OnPropertyChanged();
                    OnPropertyChanged(nameof(CanControl));
                    OnPropertyChanged(nameof(IsThrottlingEnabled));
                }
            }
        }

        private bool _isLocalPc;
        public bool IsLocalPc
        {
            get => _isLocalPc;
            set
            {
                if (_isLocalPc != value)
                {
                    _isLocalPc = value;
                    OnPropertyChanged();
                    OnPropertyChanged(nameof(CanControl));
                    OnPropertyChanged(nameof(IsThrottlingEnabled));
                }
            }
        }

        public bool CanControl => !IsLocalPc && !IsGateway;

        public bool IsThrottlingEnabled => CanControl && _redirect;

        // ── Tracking ──

        public DateTime TimeSinceLastArp { get; set; }

        /// <summary>Bytes sent in current monitoring cycle.</summary>
        public int BytesSent;

        /// <summary>Bytes received in current monitoring cycle.</summary>
        public int BytesReceived;

        // ── Bindable download speed ──

        private string _downloadSpeed = "—";
        public string DownloadSpeed
        {
            get => _downloadSpeed;
            set
            {
                if (_downloadSpeed != value)
                {
                    _downloadSpeed = value;
                    OnPropertyChanged();
                }
            }
        }

        // ── INotifyPropertyChanged ──

        public event PropertyChangedEventHandler PropertyChanged;

        protected void OnPropertyChanged([CallerMemberName] string propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }
}