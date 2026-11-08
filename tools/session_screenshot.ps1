# Invoked as the selected logged-on user by DropbearWin's desktop launcher.
# The client substitutes a randomly generated absolute OUTPUT_BASE path.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$base = 'OUTPUT_BASE'
$bitmap = $null
$graphics = $null
try {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    Add-Type -TypeDefinition @'
using System; using System.Text; using System.Runtime.InteropServices;
public class DropbearCaptureDesktop {
 [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
 [DllImport("user32.dll")] static extern IntPtr OpenInputDesktop(uint f, bool inherit, uint access);
 [DllImport("user32.dll")] static extern bool CloseDesktop(IntPtr h);
 [DllImport("user32.dll", CharSet=CharSet.Unicode)] static extern bool GetUserObjectInformationW(IntPtr h, int n, StringBuilder s, int size, out int needed);
 public static string InputName() {
  var h=OpenInputDesktop(0,false,1);
  if(h==IntPtr.Zero) throw new Exception("Input desktop unavailable (locked, disconnected, or access denied)");
  try { int n; var s=new StringBuilder(256); if(!GetUserObjectInformationW(h,2,s,512,out n)) throw new Exception("Cannot query input desktop"); return s.ToString(); }
  finally { CloseDesktop(h); }
 }
}
'@
    $null = [DropbearCaptureDesktop]::SetProcessDPIAware()
    $desktop = [DropbearCaptureDesktop]::InputName()
    if ($desktop -ine 'Default') { throw "Input desktop is $desktop, not Default" }
    $bounds = [System.Windows.Forms.SystemInformation]::VirtualScreen
    if ($bounds.Width -le 0 -or $bounds.Height -le 0 -or ([long]$bounds.Width * $bounds.Height) -gt 40000000) {
        throw 'Invalid desktop size or more than 40 megapixels'
    }
    $bitmap = New-Object System.Drawing.Bitmap($bounds.Width, $bounds.Height)
    $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
    $graphics.CopyFromScreen($bounds.X, $bounds.Y, 0, 0, $bounds.Size, [System.Drawing.CopyPixelOperation]::SourceCopy)
    $bitmap.Save(($base + '.png'), [System.Drawing.Imaging.ImageFormat]::Png)
    $result = @{
        session_id = [Diagnostics.Process]::GetCurrentProcess().SessionId
        windows_user = [Security.Principal.WindowsIdentity]::GetCurrent().Name
        desktop = $desktop; width = $bounds.Width; height = $bounds.Height
        capture_mode = 'virtual_desktop'
        left = $bounds.X; top = $bounds.Y
    }
} catch {
    $result = @{error = $_.ToString()}
} finally {
    if ($graphics) { $graphics.Dispose() }
    if ($bitmap) { $bitmap.Dispose() }
}
[IO.File]::WriteAllText(($base + '.json.tmp'), ($result | ConvertTo-Json -Compress), (New-Object Text.UTF8Encoding($false)))
Move-Item -LiteralPath ($base + '.json.tmp') -Destination ($base + '.json') -Force
