# SelfishNet

## Control your internet bandwidth with SelfishNet.
[Currently in development]

> [!WARNING]
> **Security Notice:** This GitHub repository (`https://github.com/nov0caina/SelfishNet`) is the **only official source** for this modern rewrite. Third-party domains (such as `selfishnet.org` and other unauthorized portals) have no affiliation with this project, distribute unauthorized copies, and may pose security risks. Do not download or execute untrusted binaries from third-party sites.


## Linux Native (Cross-Platform) Migration (Branch: linuxDevEnv_migration)

This branch contains a complete rewrite of the SelfishNet core and UI to enable native execution on **Linux** and MacOS, removing the exclusive dependency on Windows.

### Migration Rationale
The original project relied on obsolete technologies (.NET Framework 3.5, WinPcap) and native Windows libraries (`user32.dll`, `gdi32.dll`), making it impossible to run on other operating systems. This migration aims to modernize the codebase, improve stability, and offer true cross-platform support.

### Key Technological Changes

| Component | Before (Legacy) | Now (Modern/Cross-Platform) |
| :--- | :--- | :--- |
| **Framework** | .NET Framework 3.5 | **.NET 8** |
| **Interface (UI)** | Windows Forms (WinForms) | **Avalonia UI** (XAML Cross-platform) |
| **Network Driver** | PcapNet / WinPcap | **SharpPcap** (via libpcap/Npcap) |
| **Interoperability** | P/Invoke (`user32.dll`) | **Managed Native** (No external dependencies) |

### 📋 Prerequisites

#### 1. Windows 🪟

* **Framework:** .NET 8.0 SDK.
* **Driver:** Npcap (Download from [nmap.org/npcap](https://nmap.org/npcap/)).
    * *Important:* During installation, check the box **"Install Npcap in WinPcap API-compatible Mode"**.
* **Permissions:** You must run the application as **Administrator**.
---

#### 2. MacOS 🍎

* **Framework:** .NET 8.0 SDK.
* **Library:** libpcap (Usually pre-installed, or via Homebrew: `brew install libpcap`).
* **Permissions:** Execution with `sudo` is required to access network hardware.
* **Configuration:** Enable IP forwarding to allow MITM:
    `sudo sysctl -w net.inet.ip.forwarding=1`
---

#### 3. Linux 🐧

* **Framework:** .NET 8.0 SDK.
* **Library:** `libpcap-dev` package (Install via `apt`, `dnf`, or `pacman`).
* **Permissions:** Execution with `sudo` (or capabilities `cap_net_raw,cap_net_admin`).
* **Configuration:** Enable IP forwarding to allow MITM:
    `sudo sysctl -w net.ipv4.ip_forward=1`

### License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

_____________________________________________________________________________________________________________________________________

## Migración a Linux Native (Multi-Plataforma) (Rama: linuxDevEnv_migration)

> [!WARNING]
> **Aviso de Seguridad:** Este repositorio de GitHub (`https://github.com/nov0caina/SelfishNet`) es la **única fuente oficial** de este desarrollo moderno. Dominios de terceros (como `selfishnet.org` u otros portales no autorizados) no tienen relación con este proyecto, redistribuyen copias sin autorización y pueden representar riesgos de seguridad. No descargues ni ejecutes binarios de fuentes no verificadas.

Esta rama contiene la reescritura completa del núcleo y la interfaz de SelfishNet para permitir su ejecución nativa en **Linux** y MacOS, eliminando la dependencia exclusiva de Windows.

### Razones de la Migración
El proyecto original dependía de tecnologías obsoletas (.NET 3.5, WinPcap) y librerías nativas de Windows (`user32.dll`, `gdi32.dll`), lo que hacía imposible su ejecución en otros sistemas operativos. Esta migración busca modernizar el código, mejorar la estabilidad y ofrecer soporte multiplataforma real.

### 🛠 Cambios Tecnológicos Principales

| Componente | Antes (Legacy) | Ahora (Moderno/Multi-plataforma) |
| :--- | :--- | :--- |
| **Framework** | .NET Framework 3.5 | **.NET 8** |
| **Interfaz (UI)** | Windows Forms (WinForms) | **Avalonia UI** (XAML Cross-platform) |
| **Driver de Red** | PcapNet / WinPcap | **SharpPcap** (sobre libpcap/Npcap) |
| **Interoperabilidad** | P/Invoke (`user32.dll`) | **Nativa Managed** (Sin dependencias externas) |


### 📋 Prerrequisitos

#### 1. Windows 🪟

* **Framework:** SDK de .NET 8.0.
* **Driver:** Npcap (Descargar desde [nmap.org/npcap](https://nmap.org/npcap/)).
    * *Importante:* Durante la instalación, marca la casilla **"Install Npcap in WinPcap API-compatible Mode"**.
* **Permisos:** Debes ejecutar la aplicación como **Administrador**.
---

#### 2. MacOS 🍎

* **Framework:** SDK de .NET 8.0.
* **Librería:** libpcap (Usualmente preinstalada, o vía Homebrew: `brew install libpcap`).
* **Permisos:** Se requiere ejecución con `sudo` para acceder al hardware de red.
* **Configuración:** Habilitar el reenvío de IP para permitir MITM:
    `sudo sysctl -w net.inet.ip.forwarding=1`
---

#### 3. Linux 🐧

* **Framework:** SDK de .NET 8.0.
* **Librería:** Paquete `libpcap-dev` (Instalar vía `apt`, `dnf` o `pacman`).
* **Permisos:** Ejecución con `sudo` (o capacidades `cap_net_raw,cap_net_admin`).
* **Configuración:** Habilitar el reenvío de IP para permitir MITM:
    `sudo sysctl -w net.ipv4.ip_forward=1`

### Licencia
Este proyecto está licenciado bajo la Licencia MIT. Consulta el archivo [LICENSE](LICENSE) para más detalles.