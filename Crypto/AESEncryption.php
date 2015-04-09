<?php
/**
 * This file contains the class AESEncryption
 *
 * AESEncryption can safely encrypt and decrypt plain or binary data and
 * uses verification to ensure decryption was successful.
 *
 * PHP version 5
 *
 * LICENSE: This source file is subject to version 2.0 of the Apache license
 * that is available through the world-wide-web at the following URI:
 * https://www.apache.org/licenses/LICENSE-2.0.html.
 *
 * @author     Jd Daniel <dodomeki@gmail.com>
 * @license    https://www.apache.org/licenses/LICENSE-2.0.html Apache 2.0
 * @copyright  April, 09 2015 Jd Daniel
 * @version    1.0.0
 */
Namespace Crypto
{
    /**
     * Class AESEncryption
     * @package Crypto
     */
    Final Class AESEncryption
    {
        /**
         * @var string
         */
        private $key    = '',
                $iv     = '';

        /**
         * @var resource
         */
        private $mcrypt = null;

        /**
         * Construct the call optionally providing an encryption key
         *
         * @param string $key
         * @throws \RuntimeException if the PHP installation is missing criticals
         */
        public function __construct($key = null)
        {
            if (! extension_loaded ('mcrypt')) Throw New \RuntimeException('MCrypt library is not available');
            if (! extension_loaded ('hash'))   Throw New \RuntimeException('Hash library is not available');

            if (! in_array('rijndael-128', mcrypt_list_algorithms(), true))

                Throw New \RuntimeException('MCrypt library does not contain an implementation of Rijndael-128');

            if (! in_array('cbc', mcrypt_list_modes(), true))

                Throw New \RuntimeException('MCrypt library does not support CBC encryption mode');

            $this->mcrypt = mcrypt_module_open('rijndael-128', '', 'cbc', '');

            if(isset($key)) $this->SetKey($key);
        }

        /**
         * @return void
         */
        public function __destruct()
        {
            if (extension_loaded ('mcrypt') && isset($this->mcrypt))
            {
                mcrypt_module_close($this->mcrypt);
            }
        }

        /**
         * Set the key to be used for encryption and decryption operations.
         *
         * @param string $key
         * @return void
         */
        public function setKey($key)
        {
            $this->key = $this->pbkdf2('sha512', $key, hash('sha512', $key, true), 1000, mcrypt_enc_get_key_size($this->mcrypt), true);
        }

        /**
         * Encrypts data
         *
         * @param string $data
         * @param bool $rawOutput on false this method will return lowercase hexit, on true this method will return raw binary
         * @return string
         */
        public function encrypt($data, $rawOutput = false)
        {
            $data = gzcompress($data, 9);
            $hash = md5($data, true);
            $len  = pack('N', strlen($data));
            $data = $len . $hash . $data;

            // split on os type and version(s)
            $this->iv =  (version_compare(PHP_VERSION, '5.3.0', '<=') && 'win' == strtolower(substr (PHP_OS, 0, 3)))
                ? mcrypt_create_iv(mcrypt_enc_get_iv_size($this->mcrypt), MCRYPT_RAND)
                : mcrypt_create_iv(mcrypt_enc_get_iv_size($this->mcrypt), MCRYPT_DEV_URANDOM);

            $this->initialize();
            $data = mcrypt_generic($this->mcrypt, $data);
            $this->deinitialize();

            $data = $this->iv . $data;
            $this->iv = null;

            if ($rawOutput) return $data;

            $data = unpack('H*',$data);
            $data = end($data);

            return $data;
        }

        /**
         * Decrypts data
         *
         * @param string $data
         * @return string This method will return false if an error occurs
         */
        public function decrypt($data)
        {
            $data = (ctype_xdigit($data))
                ? pack ('H*',$data)
                : $data;

            $this->iv = substr ($data, 0, mcrypt_enc_get_iv_size($this->mcrypt));
            $data = substr ($data, mcrypt_enc_get_iv_size($this->mcrypt));

            $this->initialize();
            $data = mdecrypt_generic($this->mcrypt, $data);
            $this->deinitialize();

            $len = substr($data, 0, 4);
            $len = unpack('N', $len);
            $len = end($len);
            $hash = substr($data, 4, 16);
            $data = substr($data, 20, $len);
            $dataHash = md5($data, true);

            if ($this->compare($hash,$dataHash))
            {
                $data = @gzuncompress($data); // mute as gz likes to complain...
                return $data;
            }

            return false;
        }

        /**
         * Initializes the mcrypt module
         *
         * @return void
         */
        private function initialize()
        {
            mcrypt_generic_init($this->mcrypt, $this->key, $this->iv);
        }

        /**
         * Deinitializes the mcrypt module and releases memory.
         *
         * @return void
         */
        private function deinitialize()
        {
            mcrypt_generic_deinit($this->mcrypt);
        }

        /**
         * Implementation of a timing-attack safe string comparison algorithm, it will use hash_equals if it is available
         *
         * @param string $safe
         * @param string $supplied
         * @return bool
         */
        private function compare($safe, $supplied)
        {
            if (function_exists('hash_equals')) return hash_equals($safe, $supplied);

            // else lets fake it...
            $safe     .= chr(0x00);
            $supplied .= chr(0x00);

            $safeLen   = strlen($safe);
            $suppliedLen = strlen($supplied);
            $result = $safeLen - $suppliedLen;

            for ($i = 0; $i < $suppliedLen; $i++)
            {
                $result |= (ord($safe[$i % $safeLen]) ^ ord($supplied[$i]));
            }

            return 0 === $result;
        }

        /**
         * Implementation of the keyed-hash message authentication code algorithm, it will use hash_hmac if it is available
         *
         * @param string $algo
         * @param string $data
         * @param string $key
         * @param bool $rawOutput
         * @return string
         *
         * @bug method returning wrong result for joaat algorithm
         * @id 101275
         * @affects PHP installations without the hash_hmac function but they do have the joaat algorithm
         * @action wont fix
         */
        private function hmac($algo, $data, $key, $rawOutput = false)
        {
            $algo = strtolower ($algo);

            if (function_exists('hash_hmac')) return hash_hmac($algo, $data, $key, $rawOutput);

            switch ($algo)
            {
                case 'joaat':
                case 'crc32':
                case 'crc32b':
                case 'adler32':
                case 'fnv132':
                case 'fnv164':
                case 'fnv1a32':
                case 'fnv1a64':
                    $block_size = 4;
                    break;
                case 'md2':
                    $block_size = 16;
                    break;
                case 'gost':
                case 'gost-crypto':
                case 'snefru':
                case 'snefru256':
                    $block_size = 32;
                    break;
                case 'sha384':
                case 'sha512':
                case 'haval256,5':
                case 'haval224,5':
                case 'haval192,5':
                case 'haval160,5':
                case 'haval128,5':
                case 'haval256,4':
                case 'haval224,4':
                case 'haval192,4':
                case 'haval160,4':
                case 'haval128,4':
                case 'haval256,3':
                case 'haval224,3':
                case 'haval192,3':
                case 'haval160,3':
                case 'haval128,3':
                    $block_size = 128;
                    break;
                default:
                    $block_size = 64;
                    break;
            }
            $key =  (strlen($key) > $block_size)
                ? hash($algo, $key, true)
                : str_pad($key, $block_size, chr(0x00));

            $ipad = str_repeat(chr(0x36), $block_size);
            $opad = str_repeat(chr(0x5c), $block_size);

            return hash($algo, ($key ^ $opad) . hash($algo, ($key ^ $ipad) . $data, true), $rawOutput);
        }

        /**
         * Implementation of the pbkdf2 algorithm, it will use hash_pbkdf2 if it is available
         *
         * @param string $algorithm
         * @param string $password
         * @param string $salt
         * @param int $count
         * @param int $keyLength
         * @param bool $rawOutput
         * @return string
         * @throws \RuntimeException if the algorithm is not found
         */
        private function pbkdf2($algorithm, $password, $salt, $count = 1000, $keyLength = 0, $rawOutput = false)
        {
            $algorithm = strtolower ($algorithm);

            if (! in_array($algorithm, hash_algos(), true)) Throw New \RuntimeException('Hash library does not contain an implementation of ' . $algorithm);

            if (function_exists('hash_pbkdf2')) return hash_pbkdf2($algorithm, $password, $salt, $count, $keyLength, $rawOutput);

            $hash_length = strlen(hash($algorithm, '', true));

            if ($count <= 0)    $count = 1000;

            if($keyLength <= 0) $keyLength = $hash_length * 2;

            $block_count = ceil($keyLength / $hash_length);
            $output = '';

            for($i = 1; $i <= $block_count; $i++)
            {
                $last = $salt . pack('N', $i);
                $last = $xorsum = $this->hmac($algorithm, $last, $password, true);

                for ($j = 1; $j < $count; $j++)
                {
                    $xorsum ^= ($last = $this->hmac($algorithm, $last, $password, true));
                }

                $output .= $xorsum;
            }

            // return if raw output
            if ($rawOutput) return substr($output, 0, $keyLength);

            $output = unpack('H*',$output);
            $output = end ($output);

            return substr($output, 0, $keyLength);
        }
    }
}
