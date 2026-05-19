# RO Sniffing

Sniffer de paquetes TCP para Ragnarok Online (`Ragexe.exe`).
Captura tráfico de cliente/servidor y decodifica headers conocidos.

## Dependencias

- Python 3.10+
- Paquetes Python:
  - `scapy>=2.5.0`
  - `psutil>=5.9.0`
- En Windows: `Npcap` (requisito obligatorio para captura de paquetes)

Instalación:

```bash
pip install -r requirements.txt
```

## Windows (recomendado si el cliente corre en Windows)

1. Instalar [Npcap](https://npcap.com/) (obligatorio).
2. Durante el instalador de Npcap, dejar activado:
   - `Install Npcap in WinPcap API-compatible Mode`
   - `Restrict Npcap driver's access to Administrators only` (recomendado para este uso)
3. Finalizar instalación y reiniciar Windows si el instalador lo solicita.
4. Abrir PowerShell o CMD **como Administrador**.
5. Verificar que Npcap quedó disponible (opcional, pero recomendado):

```powershell
sc query npcap
```

Debería mostrar estado del servicio `npcap` (por ejemplo `STATE`).

6. Instalar dependencias de Python:

```powershell
py -m pip install -r requirements.txt
```

7. (Opcional) Listar interfaces detectadas:

```powershell
py ro_sniffer.py --list-ifaces
```

8. Ejecutar:

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

## Solución de problemas rápida (Windows)

- Error tipo "No such device" o interfaces vacías:
  - Reinstalar Npcap y confirmar modo WinPcap compatible.
- Captura vacía:
  - Ejecutar terminal como Administrador.
  - Confirmar interfaz correcta con `--list-ifaces`.
- Error de permisos:
  - Revisar que Npcap esté instalado y servicio activo (`sc query npcap`).

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
