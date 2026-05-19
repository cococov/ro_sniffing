# RO Sniffing

Sniffer de paquetes TCP para Ragnarok Online (`Ragexe.exe`).
Captura tráfico de cliente/servidor y decodifica headers conocidos.

## Dependencias

- Python 3.10+
- Paquetes Python:
  - `scapy>=2.5.0`
  - `psutil>=5.9.0`

Instalación:

```bash
pip install -r requirements.txt
```

## Windows (recomendado si el cliente corre en Windows)

1. Instalar [Npcap](https://npcap.com/) (activar compatibilidad WinPcap durante instalación).
2. Abrir PowerShell o CMD **como Administrador**.
3. Instalar dependencias:

```powershell
py -m pip install -r requirements.txt
```

4. (Opcional) Listar interfaces:

```powershell
py ro_sniffer.py --list-ifaces
```

5. Ejecutar:

```powershell
py ro_sniffer.py --ids
```

Si no captura tráfico, elegir interfaz manualmente:

```powershell
py ro_sniffer.py --ids --iface "Ethernet"
```

También puedes agregar puertos personalizados:

```powershell
py ro_sniffer.py --ids --iface "Ethernet" 6900 6121 5121
```

## Linux

Instalar dependencias:

```bash
pip3 install -r requirements.txt
```

Ejecutar con privilegios:

```bash
sudo python3 ro_sniffer.py --ids
```

## WSL + cliente en Windows

No es el escenario recomendado.

- Desde WSL no se puede inspeccionar directamente procesos Windows para detectar `Ragexe.exe`.
- La captura de tráfico puede no reflejar correctamente el tráfico del cliente Windows según interfaz/NAT.

Si el cliente corre en Windows, ejecuta el sniffer directamente en Windows.
