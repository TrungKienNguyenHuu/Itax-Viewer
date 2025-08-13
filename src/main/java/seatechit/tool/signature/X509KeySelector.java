package seatechit.tool.signature;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Iterator;
import javax.xml.crypto.*;
import javax.xml.crypto.KeySelector.Purpose;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.X509Data;

public class X509KeySelector extends KeySelector {

    public KeySelectorResult select(KeyInfo keyInfo, Purpose purpose,
                                    AlgorithmMethod method, XMLCryptoContext context) throws KeySelectorException {

        if (keyInfo == null) {
            throw new KeySelectorException("Null KeyInfo object!");
        }

        for (XMLStructure info : keyInfo.getContent()) {
            if (!(info instanceof X509Data)) {
                continue;
            }

            X509Data x509Data = (X509Data)info;
            for (Object o : x509Data.getContent()) {
                if (!(o instanceof X509Certificate)) {
                    continue;
                }

                final PublicKey key = ((X509Certificate)o).getPublicKey();
                // Debug print
                System.out.println("Found key algorithm: " + key.getAlgorithm());
                System.out.println("Required algorithm: " + method.getAlgorithm());

                if (algEquals(method.getAlgorithm(), key.getAlgorithm())) {
                    return new KeySelectorResult() {
                        public java.security.Key getKey() {
                            return key;
                        }
                    };
                }
            }
        }
        throw new KeySelectorException("No key found!");
    }

    static boolean algEquals(String algURI, String algName) {
        if (algURI.contains("#rsa-")) {
            return algName.equalsIgnoreCase("RSA");
        } else if (algURI.contains("#dsa-")) {
            return algName.equalsIgnoreCase("DSA");
        } else if (algURI.contains("#ecdsa-")) {
            return algName.equalsIgnoreCase("EC");
        }
        return false;
    }
}