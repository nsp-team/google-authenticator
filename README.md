# Summary
 This is a php library ，Google Authenticator One-time Password Algorithm in PHP

see: https://www.phpgangsta.de/2-faktor-authentifizierung-mit-dem-google-authenticator

# Installation
This library is installable via `composer`
`composer require nsp-team/simple-http`

# Usage
```injectablephp
require_once "vendor/autoload.php";

use NspTeam\Authenticator\GoogleAuthenticator;

$ga = new GoogleAuthenticator();

$secret = $ga->createSecret();
echo "Secret is: ".$secret."\n\n";

$qrCodeUrl = $ga->getQRCodeGoogleUrl('Blog', $secret);
echo "Google Charts URL for the QR-Code: ".$qrCodeUrl."\n\n";

$oneCode = $ga->getCode($secret);
echo "Checking Code '$oneCode' and Secret '$secret':\n";

$checkResult = $ga->verifyCode($secret, $oneCode, 2);    // 2 = 2*30sec clock tolerance
if ($checkResult) {
    echo 'OK';
} else {
    echo 'FAILED';
}

```
