<?php

include 'AESEncryption.php';

$key    = 'my secret key';
$string = 'hello world';

try
{
    $aes  = New Crypto\AESencryption($key); // exception can be thrown here if the class is not supported
    $data = $aes->encrypt($string, true);   // expecting return of a raw byte string
    $decr = $aes->decrypt($data);           // expecting the return of "hello world"

    echo "Expecting 'hello world': {$decr}\n";

    // encrypt something else with a different key
    $aes->SetKey('my other secret key');    // exception can be thrown here if the class is not supported
    $data2 = $aes->encrypt($string);        // return the return of a lowercase hexit string
    $decr  = $aes->decrypt($data2);         // expecting the return of "hello world"

    echo "Expecting 'hello world': {$decr}\n";

    // proof that the key was changed
    $decr = $aes->decrypt($data);           // expecting return of Boolean False

    echo "Expecting 'false': "; var_export($decr);
    echo "\n";

    // reset the key back
    $aes->SetKey($key);                     // exception can be thrown here if the class is not supported
    $decr = $aes->decrypt($data);           // expecting hello world

    echo "Expecting 'hello world': {$decr}\n";
}

catch (Exception $e)
{
    print 'Error running AESEncryption class; reason: ' . $e->getMessage ();
}