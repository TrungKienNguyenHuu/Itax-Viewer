package ihtkk.tool.signature;

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
import java.security.GeneralSecurityException;
import java.security.Principal;
import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
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
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
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
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;

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
  
  public void verifyCertificate(X509Certificate aCertificate) throws Exception
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
  }
  
  private OCSPReq generateOCSPRequest(X509Certificate issuerCert, BigInteger serialNumber)
          throws OCSPException, OperatorCreationException, CertificateException {
    Security.addProvider(new BouncyCastleProvider());

    org.bouncycastle.operator.DigestCalculatorProvider digCalcProv = 
        new org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder()
            .setProvider("BC")
            .build();
            
    CertificateID id = new CertificateID(
        digCalcProv.get(CertificateID.HASH_SHA1), 
        new JcaX509CertificateHolder(issuerCert), 
        serialNumber
    );

    OCSPReqBuilder gen = new OCSPReqBuilder();
    
    gen.addRequest(id);
    

    BigInteger nonce = BigInteger.valueOf(System.currentTimeMillis());
    Vector oids = new Vector();
    Vector values = new Vector();
    
    oids.add(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
    values.add(new X509Extension(false, new DEROctetString(nonce.toByteArray())));
    
    gen.setRequestExtensions(Extensions.getInstance(new X509Extensions(oids, values)));
    
    return gen.build();
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
  
  public void checkRevocationStatus(X509Certificate cert, X509Certificate issuerCert) throws Exception { List<String> locations = getOcspUrl(cert);
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
  
  private List<String> getOcspUrl(X509Certificate cert) throws Exception {
    List<String> ocspUrlList = getX509Extensions(cert, "1.3.6.1.5.5.7.48.1");
    if (ocspUrlList.isEmpty()) {
      throw new ITaxStatusValidException("Không thể đọc thông tin về URI dùng để kiểm tra trạng thái thu hồi của chứng thư số");
    }
    return ocspUrlList;
  }

  private List<String> getX509Extensions(X509Certificate cert, String OID) throws Exception {
    List<String> extValues = new ArrayList();
    try {
      byte[] bytes = cert.getExtensionValue(X509Extensions.AuthorityInfoAccess.getId());
      ASN1InputStream ais = new ASN1InputStream(new ByteArrayInputStream(bytes));
      ASN1OctetString octs = (ASN1OctetString)ais.readObject();
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
      throw new ITaxStatusValidException("Không có thông tin về CA trong chứng thư số");
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
        InputStream certStream = new FileInputStream(rootCertFile);
        try {
          X509Certificate trustedCertificate = loadX509CertificateFromStream(certStream);
          certArr.add(trustedCertificate);
        } catch (CertificateException certEx) {
          certEx.printStackTrace();
        } finally {
          certStream.close();
        }
      }
    }
    return (X509Certificate[])certArr.toArray(new X509Certificate[0]);
  }
  
  private boolean isIssuerCert(X509Certificate cert, X509Certificate issuerCert) { String issuerSubject = issuerCert.getSubjectDN().getName();
    String issuer = cert.getIssuerDN().getName();
    






    return (issuerSubject.equals(issuer)) && ((cert.getNotBefore().after(issuerCert.getNotBefore())) || (cert.getNotBefore().equals(issuerCert.getNotBefore()))) && (
      (cert.getNotAfter().before(issuerCert.getNotAfter())) || (cert.getNotAfter().equals(issuerCert.getNotAfter())));
  }
  
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
