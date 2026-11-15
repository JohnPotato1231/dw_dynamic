param(
    [Parameter(Mandatory = $true)][int]$ProcessId,
    [Parameter(Mandatory = $true)][string]$OutputPath,
    [string]$Password,
    [switch]$Advance
)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class SetupWindowTest {
    [StructLayout(LayoutKind.Sequential)]
    public struct Rect { public int Left, Top, Right, Bottom; }
    [DllImport("user32.dll")]
    public static extern bool GetWindowRect(IntPtr window, out Rect rect);
    [DllImport("user32.dll")]
    public static extern bool PrintWindow(IntPtr window, IntPtr dc, uint flags);
    [DllImport("user32.dll")]
    public static extern bool PostMessage(IntPtr window, uint message, IntPtr wparam, IntPtr lparam);
}
'@
$setupProcess = Get-Process -Id $ProcessId
$setupWindow = $setupProcess.MainWindowHandle
if ($setupWindow -eq 0) { throw 'The test process has no setup window.' }
if ($Advance) {
    foreach ($character in $Password.ToCharArray()) {
        $null = [SetupWindowTest]::PostMessage($setupWindow, 0x102, [IntPtr][int]$character, [IntPtr]0)
    }
    $nextPosition = [IntPtr]((503 -shl 16) -bor 235)
    $null = [SetupWindowTest]::PostMessage($setupWindow, 0x201, [IntPtr]1, $nextPosition)
    $null = [SetupWindowTest]::PostMessage($setupWindow, 0x202, [IntPtr]0, $nextPosition)
    Start-Sleep -Milliseconds 1500
}
$bounds = New-Object SetupWindowTest+Rect
if (-not [SetupWindowTest]::GetWindowRect($setupWindow, [ref]$bounds)) {
    throw 'Could not read the setup window bounds.'
}
$bitmap = New-Object System.Drawing.Bitmap ($bounds.Right - $bounds.Left), ($bounds.Bottom - $bounds.Top)
$graphics = [System.Drawing.Graphics]::FromImage($bitmap)
$dc = $graphics.GetHdc()
try {
    $captured = [SetupWindowTest]::PrintWindow($setupWindow, $dc, 2)
} finally { $graphics.ReleaseHdc($dc) }
try {
    if (-not $captured) { throw 'Setup window capture failed.' }
    $bitmap.Save($OutputPath, [System.Drawing.Imaging.ImageFormat]::Png)
} finally {
    $graphics.Dispose()
    $bitmap.Dispose()
}
Write-Output ('Captured: ' + $setupProcess.MainWindowTitle)
