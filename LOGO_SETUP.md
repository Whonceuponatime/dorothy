# Logo Setup Guide

## Current Logo Configuration

### Application Icon (Taskbar/Window Icon)
- **File Needed**: `Resources\icon.ico` (from `SEACURE(SHIELD).png`)
- **Usage**: Taskbar icon, window icon, Start Menu icon
- **Status**: ⚠️ **Action Required** - Need to convert PNG to ICO

### Installer Wizard Images
- **File**: `Resources\SEACURE(SHIELD).png`
- **Usage**: Installer wizard background and header
- **Status**: ✅ **Configured** - Already set in `installer.iss`

### Main Program Logo
- **File**: `Resources\logo.png`
- **Usage**: Large logo displayed in the main window header
- **Status**: ✅ **Configured** - Set to 200x80px in `MainWindow.xaml`

## Converting Shield PNG to ICO

You need to convert `SEACURE(SHIELD).png` to `icon.ico` for the application icon.

### Option 1: Online Converter (Easiest)
1. Go to: https://convertio.co/png-ico/ or https://www.icoconverter.com/
2. Upload `Resources\SEACURE(SHIELD).png`
3. Download the converted `icon.ico`
4. Save it as `Resources\icon.ico` (replace existing)

### Option 2: Using ImageMagick (Command Line)
```powershell
# Install ImageMagick first: winget install ImageMagick.ImageMagick
magick "Resources\SEACURE(SHIELD).png" -define icon:auto-resize=256,128,64,48,32,16 "Resources\icon.ico"
```

### Option 3: Using GIMP or Photoshop
1. Open `SEACURE(SHIELD).png`
2. Export/Save As → Choose ICO format
3. Include multiple sizes: 256x256, 128x128, 64x64, 48x48, 32x32, 16x16
4. Save as `Resources\icon.ico`

## After Creating icon.ico

Once you have `icon.ico`:
1. Place it in `Resources\icon.ico` (replacing the old one)
2. Rebuild the application: `dotnet build -c Release`
3. Rebuild the installer: `.\build-installer.ps1`

The new shield icon will appear in:
- Taskbar
- Window title bar
- Start Menu
- Desktop shortcut (if created)
- Installer wizard

