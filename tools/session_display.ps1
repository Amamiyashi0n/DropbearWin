# Executed inside the explicitly selected logged-on desktop session.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$base = 'OUTPUT_BASE'
$request = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('REQUEST_BASE64')) | ConvertFrom-Json
$result = @{session_id=[Diagnostics.Process]::GetCurrentProcess().SessionId; windows_user=[Security.Principal.WindowsIdentity]::GetCurrent().Name}
try {
    Add-Type -TypeDefinition @'
using System; using System.Collections.Generic; using System.Runtime.InteropServices;
public class DropbearDisplay {
 [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)] public struct Device {
  public uint size; [MarshalAs(UnmanagedType.ByValTStr,SizeConst=32)] public string name;
  [MarshalAs(UnmanagedType.ByValTStr,SizeConst=128)] public string description; public uint flags;
  [MarshalAs(UnmanagedType.ByValTStr,SizeConst=128)] public string id;
  [MarshalAs(UnmanagedType.ByValTStr,SizeConst=128)] public string key;
 }
 [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)] public struct Mode {
  [MarshalAs(UnmanagedType.ByValTStr,SizeConst=32)] public string device;
  public ushort spec,driver,size,extra; public uint fields;
  public int x,y; public uint orientation,fixedOutput;
  public short color,duplex,yResolution,ttOption,collate;
  [MarshalAs(UnmanagedType.ByValTStr,SizeConst=32)] public string form;
  public ushort logPixels; public uint bits,width,height,flags,frequency;
  public uint icmMethod,icmIntent,media,dither,reserved1,reserved2,panningWidth,panningHeight;
 }
 [DllImport("user32.dll",CharSet=CharSet.Unicode)] static extern bool EnumDisplayDevicesW(string device,uint n,ref Device data,uint flags);
 [DllImport("user32.dll",CharSet=CharSet.Unicode)] static extern bool EnumDisplaySettingsW(string device,int n,ref Mode data);
 [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern int ChangeDisplaySettingsExW(string device,ref Mode data,IntPtr window,uint flags,IntPtr reserved);
 [DllImport("user32.dll")] public static extern int GetSystemMetrics(int index);
 public static Device[] Devices() {
  var result=new List<Device>();
  for(uint n=0;n<64;n++) { var d=new Device(); d.size=(uint)Marshal.SizeOf(typeof(Device)); if(!EnumDisplayDevicesW(null,n,ref d,0)) break; if((d.flags&1)!=0 && (d.flags&8)==0) result.Add(d); }
  return result.ToArray();
 }
 public static Mode Get(string device,int n) {
  var m=new Mode(); m.size=(ushort)Marshal.SizeOf(typeof(Mode));
  if(!EnumDisplaySettingsW(device,n,ref m)) throw new Exception("Cannot enumerate display mode "+n+" for "+device);
  return m;
 }
 public static Mode[] Modes(string device) {
  var result=new List<Mode>();
  for(int n=0;n<1024;n++) { var m=new Mode(); m.size=(ushort)Marshal.SizeOf(typeof(Mode)); if(!EnumDisplaySettingsW(device,n,ref m)) break; result.Add(m); }
  return result.ToArray();
 }
}
'@
    function Mode-Info($m) {
        return @{width=[int]$m.width; height=[int]$m.height; refresh_hz=[int]$m.frequency;
                 bits_per_pixel=[int]$m.bits; left=$m.x; top=$m.y; orientation=[int]$m.orientation}
    }
    $devices = @([DropbearDisplay]::Devices())
    if ($devices.Count -eq 0) { throw 'No attached display is available in this session' }
    $result = @{
        session_id=[Diagnostics.Process]::GetCurrentProcess().SessionId
        windows_user=[Security.Principal.WindowsIdentity]::GetCurrent().Name
        is_remote_session=([DropbearDisplay]::GetSystemMetrics(0x1000) -ne 0)
        action=$request.action
    }
    if ($request.action -eq 'query') {
        $result.displays = @($devices | ForEach-Object {
            $d = $_
            $modes = @([DropbearDisplay]::Modes($d.name) | ForEach-Object { Mode-Info $_ } |
                Sort-Object width,height,refresh_hz,bits_per_pixel -Unique)
            @{device=$d.name; description=$d.description; primary=(($d.flags -band 4) -ne 0);
              current=(Mode-Info ([DropbearDisplay]::Get($d.name,-1))); modes=$modes}
        })
    } else {
        if ($request.device) { $chosen = @($devices | Where-Object {$_.name -eq $request.device}) }
        else { $chosen = @($devices | Where-Object {($_.flags -band 4) -ne 0}) }
        if ($chosen.Count -ne 1) { throw 'Specify one attached device returned by dropbear_session_display' }
        $device = $chosen[0].name
        $mode = [DropbearDisplay]::Get($device,-1)
        $result.device = $device
        $result.before = Mode-Info $mode
        $result.requested = @{width=$request.width; height=$request.height; refresh_hz=$request.refresh_hz}
        $mode.width = [uint32]$request.width
        $mode.height = [uint32]$request.height
        $mode.fields = 0x180000 # DM_PELSWIDTH | DM_PELSHEIGHT; preserve topology/DPI/depth.
        if ($request.refresh_hz) { $mode.frequency=[uint32]$request.refresh_hz; $mode.fields=$mode.fields -bor 0x400000 }
        $test = [DropbearDisplay]::ChangeDisplaySettingsExW($device,[ref]$mode,[IntPtr]::Zero,2,[IntPtr]::Zero)
        $result.test_code = $test
        $result.applied = $false
        $result.test_only = [bool]$request.test_only
        if ($test -ne 0) { throw "Display driver rejected CDS_TEST (code $test). RDP may require client-side dynamic resolution/reconnect." }
        if (!$request.test_only) {
            $code = [DropbearDisplay]::ChangeDisplaySettingsExW($device,[ref]$mode,[IntPtr]::Zero,0,[IntPtr]::Zero)
            $result.change_code = $code
            if ($code -ne 0) { throw "Display change failed (code $code). RDP may require client-side resizing." }
        }
        for ($attempt=0; $attempt -lt 30; $attempt++) {
            $result.after = Mode-Info ([DropbearDisplay]::Get($device,-1))
            $result.verified = ($result.after.width -eq $request.width -and $result.after.height -eq $request.height -and
                (!$request.refresh_hz -or $result.after.refresh_hz -eq $request.refresh_hz))
            if ($request.test_only -or $result.verified) { break }
            Start-Sleep -Milliseconds 100
        }
        if (!$request.test_only) {
            if (!$result.verified) { throw 'Driver returned success but actual mode did not change. Resize the RDP client or reconnect with the desired resolution.' }
            $result.applied = $true
            $result.changed = ($result.before.width -ne $result.after.width -or $result.before.height -ne $result.after.height -or $result.before.refresh_hz -ne $result.after.refresh_hz)
            $result.status = 'applied'
        } else {
            $result.status = 'test_passed'
        }
    }
    $result.virtual_screen = @{left=[DropbearDisplay]::GetSystemMetrics(76); top=[DropbearDisplay]::GetSystemMetrics(77);
                              width=[DropbearDisplay]::GetSystemMetrics(78); height=[DropbearDisplay]::GetSystemMetrics(79)}
} catch {
    if (!$result) { $result = @{} }
    $result.error = $_.ToString()
    if ($result.is_remote_session -and $request.action -eq 'set' -and $result.ContainsKey('test_code')) {
        $result.status = 'client_resize_required'
        $result.client_resize_required = $true
    } else { $result.status = 'failed' }
}
[IO.File]::WriteAllText(($base + '.json.tmp'), ($result | ConvertTo-Json -Depth 8 -Compress), (New-Object Text.UTF8Encoding($false)))
Move-Item -LiteralPath ($base + '.json.tmp') -Destination ($base + '.json') -Force
