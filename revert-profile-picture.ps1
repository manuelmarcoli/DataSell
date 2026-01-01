# Revert profile picture feature
# This script removes the profile picture upload functionality from all files

# 1. Fix profile.html
Write-Host "Reverting profile.html..."
$profilePath = "c:\Users\HEDGEHOG\Downloads\DataSell-main\public\profile.html"
$content = Get-Content $profilePath -Raw

# Remove upload handling code
$content = $content -replace '(?s)// Handle profile picture upload.*?function triggerFileInput.*?\}\s*', ''

# Remove displayProfilePicture and setupProfilePictureEventListeners functions
$content = $content -replace '(?s)// Display profile picture or initials.*?function triggerFileInput.*?\}\s*', ''

# Remove call to displayProfilePicture in updateUI
$content = $content -replace '\s*// Display profile picture\s*displayProfilePicture\(\);', ''

Set-Content $profilePath -Value $content
Write-Host "✓ profile.html reverted"

# 2. Fix index.html
Write-Host "Reverting index.html..."
$indexPath = "c:\Users\HEDGEHOG\Downloads\DataSell-main\public\index.html"
$content = Get-Content $indexPath -Raw

# Remove loadProfileData and updateUserAvatar functions
$content = $content -replace '(?s)// Load profile data including profile picture\s*async function loadProfileData.*?}`\s*function updateUserAvatar', '// Update user avatar with initials`        function updateUserAvatar'

# Remove background-image CSS support
$content = $content -replace '(\s*background-image:.*?;)', ''

# Simplify updateUserAvatar to just show initials
$updateUserAvatarMatch = $content | Select-String -Pattern 'function updateUserAvatar.*?(?=function|</script>)' -Raw
if ($updateUserAvatarMatch) {
    $simpleAvatarFunction = @"
function updateUserAvatar() {
            const avatarElement = document.getElementById('userAvatar');
            if (!avatarElement) return;
            
            if (currentUser && currentUser.displayName) {
                const names = currentUser.displayName.split(' ');
                const initials = names.map(name => name[0]).join('').toUpperCase();
                avatarElement.innerHTML = initials;
            }
        }
"@
    $content = $content -replace '(?s)function updateUserAvatar\(\).*?(?=\n\s*function|\n\s*//|document\.addEventListener)', $simpleAvatarFunction
}

# Remove await loadProfileData() from initialization
$content = $content -replace '\s*await loadProfileData\(\);\s*', '
                    '

Set-Content $indexPath -Value $content
Write-Host "✓ index.html reverted"

# 3. Fix wallet.html
Write-Host "Reverting wallet.html..."
$walletPath = "c:\Users\HEDGEHOG\Downloads\DataSell-main\public\wallet.html"
$content = Get-Content $walletPath -Raw

# Remove loadProfileData and updateUserAvatar functions
$content = $content -replace '(?s)async function loadProfileData\(\).*?function updateUserAvatar.*?(?=\n\s*function updateWalletUI)', ''

# Remove background-image CSS support
$content = $content -replace '(\s*background-image:.*?;)', ''

# Remove function calls
$content = $content -replace '\s*await loadProfileData\(\);\s*', ''
$content = $content -replace '\s*updateUserAvatar\(\);\s*', ''

Set-Content $walletPath -Value $content
Write-Host "✓ wallet.html reverted"

# 4. Fix orders.html
Write-Host "Reverting orders.html..."
$ordersPath = "c:\Users\HEDGEHOG\Downloads\DataSell-main\public\orders.html"
$content = Get-Content $ordersPath -Raw

# Remove loadProfileData and updateUserAvatar functions
$content = $content -replace '(?s)async function loadProfileData\(\).*?function updateUserAvatar.*?(?=\n\s*function loadOrders)', ''

# Remove background-image CSS support
$content = $content -replace '(\s*background-image:.*?;)', ''

# Remove function calls
$content = $content -replace '\s*await loadProfileData\(\);\s*', ''
$content = $content -replace '\s*updateUserAvatar\(\);\s*', ''

Set-Content $ordersPath -Value $content
Write-Host "✓ orders.html reverted"

# 5. Fix purchase.html
Write-Host "Reverting purchase.html..."
$purchasePath = "c:\Users\HEDGEHOG\Downloads\DataSell-main\public\purchase.html"
$content = Get-Content $purchasePath -Raw

# Remove loadProfileData and updateUserAvatar functions
$content = $content -replace '(?s)async function loadProfileData\(\).*?function updateUserAvatar.*?(?=\n\s*function updatePackages)', ''

# Remove background-image CSS support
$content = $content -replace '(\s*background-image:.*?;)', ''

# Remove function calls
$content = $content -replace '\s*await loadProfileData\(\);\s*', ''
$content = $content -replace '\s*updateUserAvatar\(\);\s*', ''

Set-Content $purchasePath -Value $content
Write-Host "✓ purchase.html reverted"

# 6. Fix server.js
Write-Host "Reverting server.js..."
$serverPath = "c:\Users\HEDGEHOG\Downloads\DataSell-main\server.js"
$content = Get-Content $serverPath -Raw

# Remove profile picture endpoints
$content = $content -replace '(?s)// Get profile picture only.*?res\.json.*?\}\);', ''
$content = $content -replace '(?s)// Upload profile picture.*?res\.status.*?\}\);', ''

# Fix GET /api/profile endpoint to remove hasProfilePicture flag if it exists
$content = $content -replace 'hasProfilePicture: !!userData\.profilePicture.*?,?\s*', ''

Set-Content $serverPath -Value $content
Write-Host "✓ server.js reverted"

# 7. Fix android-wrapper/server.js
Write-Host "Reverting android-wrapper/server.js..."
$androidServerPath = "c:\Users\HEDGEHOG\Downloads\DataSell-main\android-wrapper\server.js"
if (Test-Path $androidServerPath) {
    $content = Get-Content $androidServerPath -Raw
    
    # Remove profile picture endpoints
    $content = $content -replace '(?s)// Get profile picture only.*?res\.json.*?\}\);', ''
    $content = $content -replace '(?s)// Upload profile picture.*?res\.status.*?\}\);', ''
    
    # Fix GET /api/profile endpoint
    $content = $content -replace 'hasProfilePicture: !!userData\.profilePicture.*?,?\s*', ''
    
    Set-Content $androidServerPath -Value $content
    Write-Host "✓ android-wrapper/server.js reverted"
} else {
    Write-Host "⚠ android-wrapper/server.js not found, skipping"
}

Write-Host "`n✅ Profile picture feature successfully removed!"
Write-Host "Ready to restart server..."
