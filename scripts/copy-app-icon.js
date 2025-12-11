const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..');
const src = path.join(root, 'appicons', 'android', 'mipmap-mdpi', 'ic_launcher.png');
const destDir = path.join(root, 'public', 'images');
const destAppIcon = path.join(destDir, 'app-icon.png');
const destWebLogo2 = path.join(destDir, 'web-logo2.png');
const destWebLogo = path.join(destDir, 'web-logo.png');

try {
  fs.mkdirSync(destDir, { recursive: true });
  fs.copyFileSync(src, destAppIcon);
  fs.copyFileSync(src, destWebLogo2);
  fs.copyFileSync(src, destWebLogo);
  console.log('✅ Copied app icon to:');
  console.log(' -', destAppIcon);
  console.log(' -', destWebLogo2);
  console.log(' -', destWebLogo);
} catch (err) {
  console.error('❌ Failed to copy app icon. Make sure the source file exists:', src);
  console.error(err.message);
  process.exit(1);
}
