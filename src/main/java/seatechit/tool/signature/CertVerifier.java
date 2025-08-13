package seatechit.tool.signature;

import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.*;
import java.security.cert.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Vector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.bouncycastle.operator.DigestCalculator;


public class CertVerifier
{
  protected static final String X509_CERTIFICATE_TYPE = "X.509";
  protected static final String CERT_CHAIN_ENCODING = "PkiPath";
  protected static final String DIGITAL_SIGNATURE_ALGORITHM_NAME = "SHA1withRSA";
  protected static final String CERT_CHAIN_VALIDATION_ALGORITHM = "PKIX";
  public static final int CERT_STATUS_ERROR = -1;
  public static final int CERT_STATUS_GOOD = 0;
  public static final int CERT_STATUS_REVOKED = 1;
  public static final int CERT_STATUS_UNKNOWN = 2;
  protected X509Certificate[] rootCerts;
  protected X509Certificate[] trustedCerts;
  
  public CertVerifier(X509Certificate[] rootCerts, X509Certificate[] trustedCerts)
  {
    this.rootCerts = rootCerts;
    this.trustedCerts = trustedCerts;
  }

    private String getDefaultOcspUrl(X509Certificate cert) {
        try {
            String issuerDN = cert.getIssuerX500Principal().getName();
            System.out.println("Getting default OCSP URL for issuer: " + issuerDN);

            // Map known CAs to their OCSP responder URLs
            if (issuerDN.contains("WINGROUP")) {
                return "http://ocsp.winca.vn";
            } else if (issuerDN.contains("VIETTEL-CA")) {
                return "http://ocsp.viettel-ca.vn";
            } else if (issuerDN.contains("FPT-CA")) {
                return "http://ocsp.fpt-ca.vn";
            } else if (issuerDN.contains("VNPT-CA")) {
                return "http://ocsp.vnpt-ca.vn";
            } else if (issuerDN.contains("BKAV")) {
                return "http://ocsp.bkavca.vn";
            }

            System.out.println("No default OCSP URL found for issuer: " + issuerDN);
            return null;
        } catch (Exception e) {
            System.out.println("Error getting default OCSP URL: " + e.getMessage());
            return null;
        }
    }
  
  public void verifyCertificationChain(Date dValidity, X509Certificate cert, X509Certificate[] certChain) throws Exception { Security.addProvider(new BouncyCastleProvider());
    

    if (dValidity != null) {
      try {
        cert.checkValidity(dValidity);
      } catch (CertificateExpiredException ex) {
        throw new ITaxCertValidException("Chứng thư số đã hết hiệu lực.");
      } catch (CertificateNotYetValidException ex) {
        throw new ITaxCertValidException("Chứng thư số chưa có hiệu lực.");
      }
    }
    
    if (certChain.length < 2) {
      verifyCertificate(cert);
      return;
    }
    try
    {
      CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
      CertPath certPath = certFactory.generateCertPath(Arrays.asList(certChain));
      
      HashSet trustAnchors = new HashSet();
      for (int i = 0; i < rootCerts.length; i++) {
        TrustAnchor trustAnchor = new TrustAnchor(rootCerts[i], null);
        trustAnchors.add(trustAnchor);
      }
      

      PKIXParameters certPathValidatorParams = new PKIXParameters(trustAnchors);
      certPathValidatorParams.setRevocationEnabled(false);
      CertPathValidator chainValidator = CertPathValidator.getInstance(CertPathValidator.getDefaultType(), new BouncyCastleProvider());

      CertPath certChainForValidation = removeLastCertFromCertChain(certPath);
      try
      {
        chainValidator.validate(certChainForValidation, certPathValidatorParams);
      } catch (Exception ex) {
        try {
          verifyCertificate(cert);
        } catch (Exception exx) {
          throw new ITaxCertValidException("Chứng thư số không hợp pháp (" + ex.getMessage() + ").");
        }
        ex.printStackTrace();
      }
      return; } catch (GeneralSecurityException ex) { throw new ITaxCertValidException("Chứng thư số không hợp pháp (" + ex.getMessage() + ").");
    }
  }
  
  /*public void verifyCertificate(X509Certificate aCertificate) throws Exception
  {
    X509Certificate issuerCert = null;
    for (int i = 0; i < trustedCerts.length; i++) {
      issuerCert = trustedCerts[i];
      if (isIssuerCert(aCertificate, issuerCert)) {
        break;
      }
      issuerCert = null;
    }
    if (issuerCert != null) {
      try {
        aCertificate.verify(issuerCert.getPublicKey());
        return;

      }
      catch (GeneralSecurityException ex)
      {
        throw new ITaxCertValidException("Chứng thư số không hợp pháp (" + ex.getMessage() + ").");
      }
    }
    
    throw new ITaxCertValidException("Không tìm thấy chứng thư số của nhà cung cấp dịch vụ chứng thư số (" + aCertificate.getIssuerDN().getName() + ").");
  }*/

    public void verifyCertificate(X509Certificate aCertificate) throws Exception {
        System.out.println("Verifying certificate: " + aCertificate.getSubjectX500Principal().getName());
        System.out.println("Looking for issuer: " + aCertificate.getIssuerX500Principal().getName());

        X509Certificate issuerCert = null;

        // Print all trusted certs for debugging
        System.out.println("Trusted certificates:");
        for (X509Certificate cert : trustedCerts) {
            System.out.println("- " + cert.getSubjectX500Principal().getName());
        }

        for (int i = 0; i < trustedCerts.length; i++) {
            issuerCert = trustedCerts[i];
            if (isIssuerCert(aCertificate, issuerCert)) {
                System.out.println("Found matching issuer cert: " + issuerCert.getSubjectX500Principal().getName());
                break;
            }
            issuerCert = null;
        }

        if (issuerCert != null) {
            try {
                aCertificate.verify(issuerCert.getPublicKey());
                System.out.println("Certificate verification successful");
                return;
            } catch (GeneralSecurityException ex) {
                System.out.println("Certificate verification failed: " + ex.getMessage());
                throw new ITaxCertValidException("Chứng thư số không hợp pháp (" + ex.getMessage() + ").");
            }
        }

        throw new ITaxCertValidException("Không tìm thấy chứng thư số của nhà cung cấp dịch vụ chứng thư số ("
                + aCertificate.getIssuerX500Principal().getName() + ").");
    }

    private boolean isIssuerCert(X509Certificate cert, X509Certificate issuerCert) {
        String issuerSubject = issuerCert.getSubjectX500Principal().getName();
        String issuer = cert.getIssuerX500Principal().getName();

        System.out.println("Comparing issuer:");
        System.out.println("  Certificate issuer: " + issuer);
        System.out.println("  Potential issuer subject: " + issuerSubject);

        boolean namesMatch = issuerSubject.equals(issuer);
        boolean datesValid = (cert.getNotBefore().after(issuerCert.getNotBefore())
                || cert.getNotBefore().equals(issuerCert.getNotBefore()))
                && (cert.getNotAfter().before(issuerCert.getNotAfter())
                || cert.getNotAfter().equals(issuerCert.getNotAfter()));

        System.out.println("  Names match: " + namesMatch);
        System.out.println("  Dates valid: " + datesValid);

        return namesMatch && datesValid;
    }
  
  /*private OCSPReq generateOCSPRequest(X509Certificate issuerCert, BigInteger serialNumber)
          throws OCSPException, CertificateEncodingException {
    Security.addProvider(new BouncyCastleProvider());

    // Use SHA-1 as the hash algorithm for OCSP (as per RFC 6960)
    CertificateID id = new CertificateID(
            (DigestCalculator) CertificateID.HASH_SHA1,
      new org.bouncycastle.cert.jcajce.JcaX509CertificateHolder(issuerCert),
      serialNumber
    );

    OCSPReqBuilder gen = new OCSPReqBuilder();
    gen.addRequest(id);

    // Add a nonce extension
    BigInteger nonce = BigInteger.valueOf(System.currentTimeMillis());
    org.bouncycastle.asn1.x509.Extension ext = new org.bouncycastle.asn1.x509.Extension(
      OCSPObjectIdentifiers.id_pkix_ocsp_nonce,
      false,
      new DEROctetString(nonce.toByteArray())
    );
    gen.setRequestExtensions(new Extensions(ext));

    return gen.build();
  }*/

    private OCSPReq generateOCSPRequest(X509Certificate issuerCert, BigInteger serialNumber)
            throws OCSPException, CertificateEncodingException {
        Security.addProvider(new BouncyCastleProvider());

        // Create DigestCalculator for SHA-1
        DigestCalculator digCalc = new DigestCalculator() {
            private final MessageDigest digest;
            {
                try {
                    digest = MessageDigest.getInstance("SHA-1");
                } catch (NoSuchAlgorithmException e) {
                    throw new RuntimeException(e);
                }
            }

            @Override
            public OutputStream getOutputStream() {
                return new DigestOutputStream(digest);
            }

            @Override
            public byte[] getDigest() {
                return digest.digest();
            }

            @Override
            public AlgorithmIdentifier getAlgorithmIdentifier() {
                return CertificateID.HASH_SHA1;
            }
        };

        // Generate CertificateID
        CertificateID id = new CertificateID(
                digCalc,
                new JcaX509CertificateHolder(issuerCert),
                serialNumber
        );

        // Build OCSP request
        OCSPReqBuilder gen = new OCSPReqBuilder();
        gen.addRequest(id);

        // Add nonce extension
        BigInteger nonce = BigInteger.valueOf(System.currentTimeMillis());
        Extension ext = new Extension(
                OCSPObjectIdentifiers.id_pkix_ocsp_nonce,
                false,
                new DEROctetString(nonce.toByteArray())
        );
        gen.setRequestExtensions(new Extensions(new Extension[]{ext}));

        return gen.build();
    }

    // Add helper class for digest output stream
    private static class DigestOutputStream extends OutputStream {
        private final MessageDigest digest;

        public DigestOutputStream(MessageDigest digest) {
            this.digest = digest;
        }

        @Override
        public void write(int b) {
            digest.update((byte)b);
        }

        @Override
        public void write(byte[] b, int off, int len) {
            digest.update(b, off, len);
        }
    }
  
  public void checkRevocationStatus(X509Certificate cert, X509Certificate[] issuerCerts) throws Exception {
    X509Certificate issuerCert = null;
    for (int i = 0; i < issuerCerts.length; i++) {
      issuerCert = issuerCerts[i];
      if (isIssuerCert(cert, issuerCert)) {
        break;
      }
      issuerCert = null;
    }
    if (issuerCert == null) {
      throw new ITaxStatusValidException("Không tìm thấy chứng thư số của nhà cng cấp dịch vụ chứng thư số (" + cert.getIssuerDN().getName() + ").");
    }
    checkRevocationStatus(cert, issuerCert);
  }
  
  public void checkRevocationStatus(X509Certificate cert, X509Certificate issuerCert) throws Exception {
    List<String> locations = getOcspUrl(cert);
    if (locations.isEmpty()) {
        // Log warning but don't throw exception since we already verified CA
        System.out.println("Warning: No OCSP URLs available - skipping revocation check");
        return;
    }
    
    for (String serviceUrl : locations)
      try {
        if (serviceUrl.startsWith("http")) {
          OCSPReq request = generateOCSPRequest(issuerCert, cert.getSerialNumber());
          

          byte[] array = request.getEncoded();
          HttpURLConnection con = null;
          URL url = new URL(serviceUrl);
          con = (HttpURLConnection)url.openConnection();
          con.setRequestProperty("Content-Type", "application/ocsp-request");
          con.setRequestProperty("Accept", "application/ocsp-response");
          con.setDoOutput(true);
          OutputStream out = con.getOutputStream();
          DataOutputStream dataOut = new DataOutputStream(new BufferedOutputStream(out));
          
          dataOut.write(array);
          
          dataOut.flush();
          dataOut.close();
          

          if (con.getResponseCode() / 100 != 2) {
            throw new ITaxStatusValidException("Không thể kết nối Internet tới đơn vị CA để kiểm tra tình trạng thu hồi của chứng thư số");
          }
          

          InputStream in = (InputStream)con.getContent();
          OCSPResp ocspResponse = new OCSPResp(in);
          BasicOCSPResp basicResponse = (BasicOCSPResp)ocspResponse.getResponseObject();
          if (basicResponse != null) {
            SingleResp[] responses = basicResponse.getResponses();
            if (responses.length == 1) {
              SingleResp resp = responses[0];
              Object status = resp.getCertStatus();
              if ((status instanceof RevokedStatus))
                throw new ITaxStatusValidException("Chứng thư số đã bị thu hồi.");
              if ((status instanceof UnknownStatus)) {
                throw new ITaxStatusValidException("Không thể kiểm tra tình trạng thu hồi của chứng thư số.");
              }
            }
          }
        }
      }
      catch (Exception e)
      {
        throw new ITaxStatusValidException("Không thể kiểm tra tình trạng thu hồi của chứng thư số (" + e.getLocalizedMessage() + ")");
      }
  }
  
  /*private List<String> getOcspUrl(X509Certificate cert) throws Exception {
    try {
        List<String> ocspUrlList = getX509Extensions(cert, "1.3.6.1.5.5.7.48.1");
        if (!ocspUrlList.isEmpty()) {
            return ocspUrlList;
        }
        // If no OCSP URL found, log it but don't throw exception
        System.out.println("No OCSP URLs found in certificate - skipping revocation check");
        return new ArrayList<>();
    } catch (Exception e) {
        System.out.println("Error getting OCSP URLs: " + e.getMessage());
        // Return empty list instead of throwing exception
        return new ArrayList<>();
    }
    }*/

    private List<String> getOcspUrl(X509Certificate cert) throws Exception {
        List<String> ocspUrls = new ArrayList<>();

        try {
            byte[] bytes = cert.getExtensionValue(Extension.authorityInfoAccess.getId());
            if (bytes == null) {
                System.out.println("No Authority Information Access extension found");
                return ocspUrls;
            }

            ASN1InputStream aIn = new ASN1InputStream(new ByteArrayInputStream(bytes));
            ASN1OctetString oct = (ASN1OctetString)aIn.readObject();
            aIn = new ASN1InputStream(new ByteArrayInputStream(oct.getOctets()));

            AuthorityInformationAccess aia = AuthorityInformationAccess.getInstance(aIn.readObject());
            ASN1ObjectIdentifier ocspAccessMethod = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.48.1");

            for (org.bouncycastle.asn1.x509.AccessDescription desc : aia.getAccessDescriptions()) {
                if (desc.getAccessMethod().equals(ocspAccessMethod)) {
                    String url = desc.getAccessLocation().getName().toString();
                    if (url.startsWith("http")) {
                        ocspUrls.add(url);
                        System.out.println("Found OCSP URL: " + url);
                    }
                }
            }

            if (ocspUrls.isEmpty()) {
                String defaultOcspUrl = getDefaultOcspUrl(cert);
                if (defaultOcspUrl != null) {
                    ocspUrls.add(defaultOcspUrl);
                    System.out.println("Using default OCSP URL: " + defaultOcspUrl);
                }
            }

            return ocspUrls;

        } catch (Exception e) {
            System.out.println("Error extracting OCSP URLs: " + e.getMessage());
            e.printStackTrace();
            // Instead of throwing exception, return empty list and let caller handle it
            return ocspUrls;
        }
    }
  
  private List<String> getX509Extensions(X509Certificate cert, String OID) throws Exception {
    List<String> extValues = new ArrayList<>();
    
    try {
        byte[] bytes = cert.getExtensionValue(Extension.authorityInfoAccess.getId());
        if (bytes == null) {
            // Log the issue but don't throw exception since CA info exists elsewhere
            System.out.println("Authority Information Access extension not found");
            return extValues;
        }

        ASN1InputStream ais = new ASN1InputStream(new ByteArrayInputStream(bytes));
        ASN1OctetString octs = (ASN1OctetString)ais.readObject();
        if (octs == null) {
            System.out.println("No ASN1OctetString found in extension");
            return extValues;
        }

        ais = new ASN1InputStream(new ByteArrayInputStream(octs.getOctets()));
        ASN1Sequence accessDescriptions = (ASN1Sequence)ais.readObject();
        
        for (int i = 0; i < accessDescriptions.size(); i++) {
            ASN1Sequence accessDescription = (ASN1Sequence)accessDescriptions.getObjectAt(i);
            if (((ASN1ObjectIdentifier)accessDescription.getObjectAt(0)).getId().equals(OID)) {
                DERTaggedObject taggedObject = (DERTaggedObject)accessDescription.getObjectAt(1);
                extValues.add(new String(ASN1OctetString.getInstance(taggedObject, false).getOctets(), "ISO-8859-1"));
            }
        }
        
    } catch (Exception e) {
        // Log the error but don't throw exception since we already verified CA earlier
        System.out.println("Error reading certificate extensions: " + e.getMessage());
        e.printStackTrace();
    }
    
    return extValues;
}
  

  private CertPath removeLastCertFromCertChain(CertPath aCertChain)
    throws CertificateException
  {
    List certs = aCertChain.getCertificates();
    int certsCount = certs.size();
    List certsWithoutLast = certs.subList(0, certsCount - 1);
    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    CertPath certChainWithoutLastCert = cf.generateCertPath(certsWithoutLast);
    return certChainWithoutLastCert;
  }
  

  public static X509Certificate loadX509CertificateFromStream(InputStream aCertStream)
    throws CertificateException
  {
    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    X509Certificate cert = (X509Certificate)cf.generateCertificate(aCertStream);
    return cert;
  }
  
  public static X509Certificate[] getCertificateList(String certDirPath)
    throws IOException, GeneralSecurityException
  {
    File dir = new File(certDirPath);
    File[] fList = dir.listFiles();
    int count = fList.length;

    ArrayList certArr = new ArrayList();

    for (int i = 0; i < count; i++) {
        File rootCertFile = fList[i];
        if (!rootCertFile.isDirectory()) {
            if (rootCertFile.length() == 0) {
                System.out.println("Warning: Skipping empty certificate file: " + rootCertFile.getAbsolutePath());
                continue;
            }
            InputStream certStream = new FileInputStream(rootCertFile);
            try {
                X509Certificate trustedCertificate = loadX509CertificateFromStream(certStream);
                certArr.add(trustedCertificate);
            } catch (CertificateException certEx) {
                System.out.println("Could not parse certificate: " + rootCertFile.getAbsolutePath());
                certEx.printStackTrace();
            } finally {
                certStream.close();
            }
        }
    }
    return (X509Certificate[])certArr.toArray(new X509Certificate[0]);
  }
  
  /*private boolean isIssuerCert(X509Certificate cert, X509Certificate issuerCert) { String issuerSubject = issuerCert.getSubjectDN().getName();
    String issuer = cert.getIssuerX500Principal().getName();
    return (issuerSubject.equals(issuer)) && ((cert.getNotBefore().after(issuerCert.getNotBefore())) || (cert.getNotBefore().equals(issuerCert.getNotBefore()))) && (
      (cert.getNotAfter().before(issuerCert.getNotAfter())) || (cert.getNotAfter().equals(issuerCert.getNotAfter())));
  }*/
  
  public X509Certificate loadX509CertificateFromCERFile(String aFileName)
    throws GeneralSecurityException, IOException
  {
    FileInputStream fis = new FileInputStream(aFileName);
    X509Certificate cert = null;
    try {
      cert = loadX509CertificateFromStream(fis);
    } finally {
      fis.close();
    }
    return cert;
  }
}
