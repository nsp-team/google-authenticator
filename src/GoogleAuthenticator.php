<?php

namespace NspTeam\Authenticator;

use Exception;

class GoogleAuthenticator
{

    protected $codeLength = 6;

    /**
     * Get array with all 32 characters for decoding from/encoding to base32.
     *
     * @return array
     */
    private function getBase32LookupTable(): array
    {
        return array(
            'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', //  7
            'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', // 15
            'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', // 23
            'Y', 'Z', '2', '3', '4', '5', '6', '7', // 31
            '=',  // padding char
        );
    }

    /**
     * Helper class to decode base32.
     *
     * @param $secret
     *
     * @return bool|string
     */
    private function base32Decode($secret)
    {
        if (empty($secret)) {
            return '';
        }

        $base32chars = $this->getBase32LookupTable();
        $base32charsFlipped = array_flip($base32chars);

        $paddingCharCount = substr_count($secret, $base32chars[32]);
        $allowedValues = array(6, 4, 3, 1, 0);
        if (!in_array($paddingCharCount, $allowedValues)) {
            return false;
        }
        for ($i = 0; $i < 4; ++$i) {
            if ($paddingCharCount === $allowedValues[$i] &&
                substr($secret, -($allowedValues[$i])) !== str_repeat($base32chars[32], $allowedValues[$i])) {
                return false;
            }
        }
        $secret = str_replace('=', '', $secret);
        $secret = str_split($secret);
        $binaryString = '';
        for ($i = 0, $iMax = count($secret); $i < $iMax; $i += 8) {
            $x = '';
            if (!in_array($secret[$i], $base32chars, true)) {
                return false;
            }
            for ($j = 0; $j < 8; ++$j) {
                $x .= str_pad(base_convert(@$base32charsFlipped[@$secret[$i + $j]], 10, 2), 5, '0', STR_PAD_LEFT);
            }
            $eightBits = str_split($x, 8);
            foreach ($eightBits as $zValue) {
                $binaryString .= (($y = chr(base_convert($zValue, 2, 10))) || ord($y) === 48) ? $y : '';
            }
        }

        return $binaryString;
    }

    /**
     * Create new secret.
     * 16 characters, randomly chosen from the allowed base32 characters.
     * @param int $secretLength
     * @return string
     * @throws \Exception
     */
    public function createSecret(int $secretLength = 16): string
    {
        $validChars = $this->getBase32LookupTable();
        // Valid secret lengths are 80 to 640 bits
        if ($secretLength < 16 || $secretLength > 128) {
            throw new Exception('Bad secret length');
        }

        $secret = '';
        $rnd = random_bytes($secretLength);
        for ($i = 0; $i < $secretLength; ++$i) {
            $secret .= $validChars[ord($rnd[$i]) & 31];
        }

        return $secret;
    }

    /**
     * Calculate the code, with given secret and point in time.
     *
     * @param string $secret
     * @param float|null $timeSlice
     *
     * @return string
     */
    public function getCode(string $secret, float $timeSlice = null): string
    {
        if ($timeSlice === null) {
            $timeSlice = (float)(time() / 30);
        }

        $secretKey = $this->base32Decode($secret);

        // Pack time into binary string
        $time = chr(0) . chr(0) . chr(0) . chr(0) . pack('N*', $timeSlice);
        // Hash it with users secret key
        $hm = hash_hmac('SHA1', $time, $secretKey, true);
        // Use last nipple of result as index/offset
        $offset = ord(substr($hm, -1)) & 0x0F;
        // grab 4 bytes of the result
        $hashpart = substr($hm, $offset, 4);

        // Unpak binary value
        $value = unpack('N', $hashpart);
        $value = $value[1];
        // Only 32 bits
        $value &= 0x7FFFFFFF;

        $modulo = 10 ** $this->codeLength;

        return str_pad($value % $modulo, $this->codeLength, '0', STR_PAD_LEFT);
    }

    /**
     * Get QR-Code URL for image, from google charts.
     *
     * @param string $name
     * @param string $secret
     * @param string|null $title
     * @param array $params
     *
     * @return string
     */
    public function getQRCodeGoogleUrl(string $name, string $secret, string $title = null, array $params = array()): string
    {
        if (!empty($params) && (int)$params['width'] > 0) {
            $width = (int)$params['width'];
        } else {
            $width = 200;
        }
        if (!empty($params) && (int)$params['height'] > 0) {
            $height = (int)$params['height'];
        } else {
            $height = 200;
        }
        if (!empty($params) && in_array($params['level'], array('L', 'M', 'Q', 'H'))) {
            $level = $params['level'];
        } else {
            $level = 'M';
        }

        $urlencoded = urlencode('otpauth://totp/' . $name . '?secret=' . $secret . '');
        if (isset($title)) {
            $urlencoded .= urlencode('&issuer=' . urlencode($title));
        }

        return "https://api.qrserver.com/v1/create-qr-code/?data=$urlencoded&size=${width}x${height}&ecc=$level";
    }

    /**
     * Check if the code is correct. This will accept codes starting from $discrepancy*30sec ago to $discrepancy*30sec from now.
     *
     * @param string $secret
     * @param string $code
     * @param int $discrepancy This is the allowed time drift in 30 second units (8 means 4 minutes before or after)
     * @param float|null $currentTimeSlice time slice if we want use other that time()
     *
     * @return bool
     */
    public function verifyCode(string $secret, string $code, int $discrepancy = 1, float $currentTimeSlice = null): bool
    {
        if ($currentTimeSlice === null) {
            $currentTimeSlice = (float)(time() / 30);
        }

        if (strlen($code) !== 6) {
            return false;
        }

        for ($i = -$discrepancy; $i <= $discrepancy; ++$i) {
            $calculatedCode = $this->getCode($secret, $currentTimeSlice + $i);
            if ($this->timingSafeEquals($calculatedCode, $code)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Set the code length, should be >=6.
     *
     * @param int $length
     *
     * @return GoogleAuthenticator
     */
    public function setCodeLength(int $length): GoogleAuthenticator
    {
        $this->codeLength = $length;

        return $this;
    }

    /**
     * A timing safe equals comparison
     * more info here: http://blog.ircmaxell.com/2014/11/its-all-about-time.html.
     *
     * @param string $safeString The internal (safe) value to be checked
     * @param string $userString The user submitted (unsafe) value
     *
     * @return bool True if the two strings are identical
     */
    private function timingSafeEquals(string $safeString, string $userString): bool
    {
        if (function_exists('hash_equals')) {
            return hash_equals($safeString, $userString);
        }
        $safeLen = strlen($safeString);
        $userLen = strlen($userString);

        if ($userLen !== $safeLen) {
            return false;
        }

        $result = 0;
        for ($i = 0; $i < $userLen; ++$i) {
            $result |= (ord($safeString[$i]) ^ ord($userString[$i]));
        }

        // They are only identical strings if $result is exactly 0...
        return $result === 0;
    }
}