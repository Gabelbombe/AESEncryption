<?php
/**
 * Jd Daniel
 *
 * Run with: php -f StandaloneLibrary.php
 *
 */
Namespace Crypto
{
    /**
     * Interface KMSServiceInterface
     */
    Interface KMSServiceInterface
    {
        public function encrypt($plaintext);
        public function decrypt($ciphertext);
    }

    /**
     * Class KMSServiceOpenSSL
     * @implements KMSServiceInterface
     */
    Class KMSServiceOpenSSL Implements KMSServiceInterface
    {
        protected $keySize  = 0;

        private $ivSize     = '',
                $iv         = '';

        /**
         * Set necessities...
         *
         * @param string $key
         * @param string $keyword
         */
        public function __construct($key = 'generic', $keyword = 'keyword', $crypt = false)
        {
            $strong         = true; // pass by ref...
            $this->ivSize   = openssl_cipher_iv_length('AES-256-CBC');

            // See: http://www.google.com/search?q=openssl_random_pseudo_bytes+slow
            $this->iv       = openssl_random_pseudo_bytes($this->ivSize, $strong);
            $this->key      = $keyword;

            $this->crypt    = $crypt; // really not needed as we shouldn't be base64'ing any of this.....
        }

        /**
         * You're method here will be the decrypt_whatever
         * this is stupid overkill and a waste of cycles....
         * ~jd

         * @param bool $enc_aes
         * @return string
         */
        private function getAESKey($enc_aes = false)
        {
            return $this->key;
        }

        /**
         * Runs encrypt whether we have the OpenSSL mod or not by leveraging *nix
         *
         * @param $text
         * @return string
         */
        public function encrypt($text)
        {
            return (! function_exists('openssl_encrypt'))
                ? exec('echo "'.trim($text).'" |openssl enc -AES-256-CBC -base64 -nosalt -K '.bin2hex($this->getAESKey()).' -iv '.bin2hex($this->iv))
                : openssl_encrypt(trim($text), 'AES-256-CBC', $this->getAESKey(), false, $this->iv);
        }

        /**
         * Runs decrypt whether we have the OpenSSL mod or not by leveraging *nix
         *
         * @param $cipher
         * @return string
         */
        public function decrypt($cipher)
        {
            return (! function_exists('openssl_decrypt'))
                ? exec('echo "'.trim($cipher).'" |openssl enc --AES-256-CBC -d -base64 -nosalt -K '.bin2hex($this->getAESKey()).' -iv '.bin2hex($this->iv))
                : openssl_decrypt(trim($cipher), 'AES-256-CBC', $this->getAESKey(), false, $this->iv);
        }
    }
}

// generic namespace so collisions don't happen while trying to run out of band code...
Namespace
{
    $crypto = New \Crypto\KMSServiceOpenSSL();

    echo "PHP OpenSSL: ";
    echo function_exists('openssl_encrypt') ? "Yes\n" : "No\n";

    echo 'Encrypted:   ';
    echo $cypher = $crypto->encrypt('The truth is out there, I just cant remember the url...') . "\n";

    echo 'Decrypted:   ';
    echo $crypto->decrypt($cypher) . "\n";

        echo "\n";

    unset($crypto, $cypher); // fin..
}