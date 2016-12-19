using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace pfxTest
{
    class Program
    {
        static void Main(string[] args)
        {
            // 在personal（个人）里面创建一个foo的证书  
            DataCertificate.CreateCertWithPrivateKey("foo", "C:\\Program Files (x86)\\Windows Kits\\8.1\\bin\\x64\\makecert.exe");

            // 获取证书  
            X509Certificate2 c1 = DataCertificate.GetCertificateFromStore("foo");

            string keyPublic = c1.PublicKey.Key.ToXmlString(false);  // 公钥  
            string keyPrivate = c1.PrivateKey.ToXmlString(true);  // 私钥  

            string cypher = DataCertificate.RSAEncrypt(keyPublic, "程序员");  // 加密  
            string plain = DataCertificate.RSADecrypt(keyPrivate, cypher);  // 解密  

            Debug.Assert(plain == "程序员");

            // 生成一个cert文件  
            DataCertificate.ExportToCerFile("foo", "d:\\mycert\\foo.cer");

            X509Certificate2 c2 = DataCertificate.GetCertFromCerFile("d:\\mycert\\foo.cer");

            string keyPublic2 = c2.PublicKey.Key.ToXmlString(false);

            bool b = keyPublic2 == keyPublic;
            string cypher2 = DataCertificate.RSAEncrypt(keyPublic2, "程序员2");  // 加密  
            string plain2 = DataCertificate.RSADecrypt(keyPrivate, cypher2);  // 解密, cer里面并没有私钥，所以这里使用前面得到的私钥来解密  

            Debug.Assert(plain2 == "程序员2");  

            // 生成一个pfx， 并且从store里面删除  
            DataCertificate.ExportToPfxFile("foo", "d:\\mycert\\foo.pfx", "111", true);

            X509Certificate2 c3 = DataCertificate.GetCertificateFromPfxFile("d:\\mycert\\foo.pfx", "111");

            string keyPublic3 = c3.PublicKey.Key.ToXmlString(false);  // 公钥  
            string keyPrivate3 = c3.PrivateKey.ToXmlString(true);  // 私钥  

            string cypher3 = DataCertificate.RSAEncrypt(keyPublic3, "程序员3");  // 加密  
            string plain3 = DataCertificate.RSADecrypt(keyPrivate3, cypher3);  // 解密  

            Debug.Assert(plain3 == "程序员3");
        }
    }
}
