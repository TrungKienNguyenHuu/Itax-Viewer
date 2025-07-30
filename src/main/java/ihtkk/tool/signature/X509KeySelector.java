package ihtkk.tool.signature;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Iterator;
import java.util.List;
import javax.xml.crypto.*;
import javax.xml.crypto.KeySelector.Purpose;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.X509Data;

public class X509KeySelector extends javax.xml.crypto.KeySelector
{
  public X509KeySelector() {}
  
  public KeySelectorResult select(KeyInfo keyInfo, KeySelector.Purpose purpose, AlgorithmMethod method, XMLCryptoContext context) throws KeySelectorException
  {
    Iterator ki = keyInfo.getContent().iterator();
    while (ki.hasNext()) {
      XMLStructure info = (XMLStructure)ki.next();
      if ((info instanceof X509Data))
      {
        X509Data x509Data = (X509Data)info;
        Iterator xi = x509Data.getContent().iterator();
        while (xi.hasNext()) {
          Object o = xi.next();
          if ((o instanceof X509Certificate))
          {
            final PublicKey key = ((X509Certificate)o).getPublicKey();
            

            if (algEquals(method.getAlgorithm(), key.getAlgorithm()))
              new KeySelectorResult()
              {
                public java.security.Key getKey() { return key; }
              };
          }
        }
      }
    }
    throw new KeySelectorException("No key found!");
  }
  





  static boolean algEquals(String algURI, String algName)
  {
    return true;
  }
}
