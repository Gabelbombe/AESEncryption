<?php require dirname(__DIR__) . '/Crypto/AESEncryption.php';

Class ClassHasAttributesTest Extends \PHPUnit_Framework_TestCase
{
    public function testHasAttributes()
    {
        $this->assertClassHasAttribute('key',    '\Crypto\AESEncryption');
        $this->assertClassHasAttribute('iv',     '\Crypto\AESEncryption');
        $this->assertClassHasAttribute('mcrypt', '\Crypto\AESEncryption');
    }
}