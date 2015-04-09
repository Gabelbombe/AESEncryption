## Description


This class will first take the supplied encryption key and run it through the PBKDF2 implementation using the 
SHA-512 algorithm at 1000 iterations.

When encrypting data this class will compress the data and compute an md5 digest of the compressed data before 
encryption. It will also calculate the length of the data after compression. These calculated values are then 
encrypted with with the compressed data and the IV is prepended to the encrypted output.

A new IV is generated using dev/urandom before each encryption operation. If the script is running on a Windows 
machine and the PHP version is less than 5.3, the class will use MCRYPT_RAND to generate an IV.

Depending on if parameter $raw_output is true or false, the encryption method will return lowercase hexit by 
default or raw binary of the encrypted data.

Decryption will reverse the encryption process and check that the computed md5 digest is equal to the stored md5 
digest that was encrypted with the data. If the hashes are not the same, the decryption method will return false. 
It will also use the stored length of the compressed data to ensure all padding is removed before decompression.

This class uses Rijndael 128 in CBC mode.

This class will work cross platform and has been tested on PHP 5.2, 5.3, 5.4, 5.5 and 5.6

## Testing

From the command line, run the following:

    php -f run.php
    
## Requirements

 * [PHP 5+]        (http://php.net/)
 * [Mcrypt Module] (http://php.net/manual/en/book.mcrypt.php)
 * [Hash Module]   (http://php.net/manual/en/book.hash.php)
 * [CType Module]  (http://php.net/manual/en/book.ctype.php)