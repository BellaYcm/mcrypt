<?php
/**
 * Created by PhpStorm.
 * User: sunke_sk
 * Date: 2015/3/3
 * Time: 16:45
 */
class Mcrypt{
    public function crypt()
    {
        var_dump($this->encrypt("sdpadsa1233adad","123"));
        var_dump($this->decrypt("jsPa3XAzq/OkkH95AMflYAG9h1aFIkiutiDCkqSRg/muw8hbNzYpENX4G4kdH4KyjadUV7gS/gU3fVMFE4rf25","123"));
    }

    function encrypt($decrypted, $password, $salt='!kQm*fF3pXe1Kbm%9') {
// Build a 256-bit $key which is a SHA256 hash of $salt and $password.
        $key = hash('SHA256', $salt . $password, true);#生成32位字符串
// Build $iv and $iv_base64.  We use a block size of 128 bits (AES compliant) and CBC mode.  (Note: ECB mode is inadequate as IV is not used.)
        srand(); $iv = mcrypt_create_iv(mcrypt_get_iv_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_CBC), MCRYPT_RAND);#初始化向量
        if (strlen($iv_base64 = rtrim(base64_encode($iv), '=')) != 22) return false;
// Encrypt $decrypted and an MD5 of $decrypted using $key.  MD5 is fine to use here because it's just to verify successful decryption.
        $encrypted = base64_encode(mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $key, $decrypted . md5($decrypted), MCRYPT_MODE_CBC, $iv));#加密的时候原值上加md5
// We're done!
        return $iv_base64.$encrypted;
    }

    function decrypt($encrypted, $password, $salt='!kQm*fF3pXe1Kbm%9') {
// Build a 256-bit $key which is a SHA256 hash of $salt and $password.
        $key = hash('SHA256', $salt . $password,true);#true 2进制
// Retrieve $iv which is the first 22 characters plus ==, base64_decoded.
        $iv = base64_decode(substr($encrypted, 0, 22) . '==');#使用 MIME base64 对数据进行编码 减少33%空间,也可重新写
// Remove $iv from $encrypted.
        $encrypted = substr($encrypted, 22);
// Decrypt the data.  rtrim won't corrupt the data because the last 32 characters are the md5 hash; thus any \0 character has to be padding.
        $decrypted = rtrim(mcrypt_decrypt(MCRYPT_RIJNDAEL_128, $key, base64_decode($encrypted), MCRYPT_MODE_CBC, $iv), "\0\4");
// Retrieve $hash which is the last 32 characters of $decrypted.
        $hash = substr($decrypted, -32);//算出md5加密的后32位字符
// Remove the last 32 characters from $decrypted.
        $decrypted = substr($decrypted, 0, -32);
// Integrity check.  If this fails, either the data is corrupted, or the password/salt was incorrect.
        if (md5($decrypted) != $hash) return false;
// Yay!
        return $decrypted;
    }
    function easyMcrypt(){
        $str =123444; //加密内容
        $key = "key:111"; //密钥
        $cipher = MCRYPT_DES; //密码类型
        $modes = MCRYPT_MODE_ECB; //密码模式
        $iv = mcrypt_create_iv(mcrypt_get_iv_size($cipher,$modes),MCRYPT_RAND);//初始化向量
        echo "加密明文：".$str."<p>";
        $str_encrypt = base64_encode(mcrypt_encrypt($cipher,$key,$str,$modes,$iv)); //加密函数
        echo "加密密文：".$str_encrypt." <p>";
        $str_decrypt = mcrypt_decrypt($cipher,$key,base64_decode("SfpO+eWzU9k="),$modes,$iv); //解密函数
        echo "还原：".$str_decrypt;
    }


}
?>