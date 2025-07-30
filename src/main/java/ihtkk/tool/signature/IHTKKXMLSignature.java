package ihtkk.tool.signature;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import javax.security.auth.x500.X500Principal;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.XMLObject;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignature.SignatureValue;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;


public class IHTKKXMLSignature
{
  private X509Certificate[] rootCerts;
  private X509Certificate[] trustedCerts;
  
  public IHTKKXMLSignature(X509Certificate[] rootCerts, X509Certificate[] trustedCerts)
  {
    this.rootCerts = rootCerts;
    this.trustedCerts = trustedCerts;
  }
  
  public void signXMLFile(X509Certificate cert, PrivateKey privateKey, String fileName) throws Exception { DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    dbf.setNamespaceAware(true);
    Document doc = dbf.newDocumentBuilder().parse(new FileInputStream(fileName));
    
    signXMLDoc(cert, privateKey, doc);
    

    OutputStream os = new FileOutputStream(fileName);
    TransformerFactory tf = TransformerFactory.newInstance();
    Transformer trans = tf.newTransformer();
    trans.transform(new DOMSource(doc), new StreamResult(os));
  }
  
  public void signXMLDoc(X509Certificate cert, PrivateKey privateKey, Document doc) throws Exception { String objID = "signedtaxreturn";
    XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");
    NodeList nl = doc.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Signature");
    objID = objID + Integer.toString(nl.getLength());
    
    Node invoice = doc.getDocumentElement();
    XMLStructure content = new DOMStructure(invoice);
    XMLObject obj = fac.newXMLObject(Collections.singletonList(content), objID, null, null);
    


    Reference ref = fac.newReference("#" + objID, fac.newDigestMethod("http://www.w3.org/2000/09/xmldsig#sha1", null));
    

    SignedInfo si = 
      fac.newSignedInfo(fac.newCanonicalizationMethod("http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments", (C14NMethodParameterSpec) null),
      fac.newSignatureMethod("http://www.w3.org/2000/09/xmldsig#rsa-sha1", null), Collections.singletonList(ref));
    

    KeyInfoFactory kif = fac.getKeyInfoFactory();
    List x509Content = new ArrayList();
    x509Content.add(cert.getSubjectX500Principal().getName());
    x509Content.add(cert);
    X509Data xd = kif.newX509Data(x509Content);
    KeyInfo ki = kif.newKeyInfo(Collections.singletonList(xd));
    

    XMLSignature signature = fac.newXMLSignature(si, ki, Collections.singletonList(obj), null, null);
    


    DOMSignContext dsc = new DOMSignContext(privateKey, doc);
    

    signature.sign(dsc);
  }
  
  public void verifyXMLSignature(String fileName)
    throws Exception
  {
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    dbf.setNamespaceAware(true);
    Document doc = dbf.newDocumentBuilder().parse(new FileInputStream(fileName));
    verifyXMLSignature(doc);
  }
  
  public Collection verifyXMLSignature(Document doc) { CertVerifier certVerifier = new CertVerifier(rootCerts, trustedCerts);
    
    ArrayList resultArr = new ArrayList();
    X509Certificate[] certChain = null;
    

    XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");
    
    NodeList signl = doc.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Signature");
    
    String xPath_data = "/HSoThueDTu/HSoKhaiThue";
    String referenceURI = "";
    Node nodeToSign = null;
    NodeList nodes = null;
    boolean checkSignXpath = false;
    try {
      if (xPath_data == null)
        throw new ITaxSigValidException("Không tìm thấy node qua PATH: " + xPath_data);
      String[] elemData = xPath_data.split("/");
      if (elemData == null)
        throw new ITaxSigValidException("Không tìm thấy node qua PATH: " + xPath_data);
      String nodeDataSig = elemData[(elemData.length - 1)];
      nodes = doc.getElementsByTagName(nodeDataSig);
      if (nodes.getLength() > 0) {
        nodeToSign = nodes.item(0);
        if (nodeToSign == null) {
          throw new ITaxSigValidException("Không tìm thấy node qua PATH: " + xPath_data);
        }
        NamedNodeMap atts = nodeToSign.getAttributes();
        int i = 0;
        do { String attNamr = atts.item(i) != null ? atts.item(i)
            .getNodeName() : null;
          if ("id".equals(attNamr)) {
            referenceURI = atts.item(i).getTextContent();
          }
          i++; if (atts == null) break; } while (i < atts.getLength());



      }
      else
      {


        throw new ITaxSigValidException("Không tìm thấy node qua PATH: " + xPath_data);
      }
      

    }
    catch (ITaxSigValidException ex)
    {
      checkSignXpath = true;
      

      if (!checkSignXpath) {
        nodeToSign = nodes.item(0);
      }
      

      for (int i = 0; i < signl.getLength(); i++) {
        XMLSignatureValidationResult result = new XMLSignatureValidationResult();
        try
        {
          try {
            Element tempNode = (Element)signl.item(i);
            Element timeStamp = (Element)tempNode.getElementsByTagName("DateTimeStamp").item(0);
            result.setTimeStamp(timeStamp.getAttribute("DateTime"));
          }
          catch (Exception e)
          {
            result.setTimeStamp("");
          }
          DOMValidateContext valContext = new DOMValidateContext(new X509KeySelector(), signl.item(i));
          if (!checkSignXpath) {
            valContext.setIdAttributeNS((Element)nodeToSign, null, "id");
          }
          
          XMLSignature signature = fac.unmarshalXMLSignature(valContext);
          certChain = getCertificateChain(signature.getKeyInfo());
          result.setCertChain(certChain);
          

          verifyXMLSignature(signature, valContext);
          


          certVerifier.verifyCertificationChain(null, certChain[0], certChain);
          

          certVerifier.checkRevocationStatus(certChain[0], trustedCerts);
        }
        catch (Exception ex) {
          if ((ex instanceof ITaxSigValidException)) {
            result.setValidStatus(XMLSignatureValidationResult.SIG_STATUS_ERROR);
          } else if ((ex instanceof ITaxCertValidException)) {
            result.setValidStatus(XMLSignatureValidationResult.SIG_STATUS_ERROR);
          } else if ((ex instanceof ITaxStatusValidException)) {
            result.setValidStatus(XMLSignatureValidationResult.SIG_STATUS_WARNING);
          }
          result.setValidMessage(ex.getMessage());
        }
        resultArr.add(result);
      } }
    return resultArr;
  }
  
  public Collection verifyXMLSignature(Document doc, String xPath_data) { CertVerifier certVerifier = new CertVerifier(rootCerts, trustedCerts);
    
    ArrayList resultArr = new ArrayList();
    X509Certificate[] certChain = null;
    

    XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");
    
    NodeList signl = doc.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Signature");
    
    String referenceURI = "";
    Node nodeToSign = null;
    NodeList nodes = null;
    boolean checkSignXpath = false;
    try {
      if (xPath_data == null)
        throw new ITaxSigValidException("Không tìm thấy node qua PATH: " + xPath_data);
      String[] elemData = xPath_data.split("/");
      if (elemData == null)
        throw new ITaxSigValidException("Không tìm thấy node qua PATH: " + xPath_data);
      String nodeDataSig = elemData[(elemData.length - 1)];
      nodes = doc.getElementsByTagName(nodeDataSig);
      if (nodes.getLength() > 0) {
        nodeToSign = nodes.item(0);
        if (nodeToSign == null) {
          throw new ITaxSigValidException("Không tìm thấy node qua PATH: " + xPath_data);
        }
        NamedNodeMap atts = nodeToSign.getAttributes();
        int i = 0;
        do { String attNamr = atts.item(i) != null ? atts.item(i)
            .getNodeName() : null;
          if ("id".equals(attNamr)) {
            referenceURI = atts.item(i).getTextContent();
          }
          i++; if (atts == null) break; } while (i < atts.getLength());



      }
      else
      {


        throw new ITaxSigValidException("Không tìm thấy node qua PATH: " + xPath_data);
      }
      

    }
    catch (ITaxSigValidException ex)
    {
      checkSignXpath = true;
      

      if (!checkSignXpath) {
        nodeToSign = nodes.item(0);
      }
      

      for (int i = 0; i < signl.getLength(); i++) {
        XMLSignatureValidationResult result = new XMLSignatureValidationResult();
        try
        {
          try {
            Element tempNode = (Element)signl.item(i);
            Element timeStamp = (Element)tempNode.getElementsByTagName("DateTimeStamp").item(0);
            result.setTimeStamp(timeStamp.getAttribute("DateTime"));
          }
          catch (Exception e)
          {
            result.setTimeStamp("");
          }
          DOMValidateContext valContext = new DOMValidateContext(new X509KeySelector(), signl.item(i));
          if (!checkSignXpath) {
            valContext.setIdAttributeNS((Element)nodeToSign, null, "id");
          }
          
          XMLSignature signature = fac.unmarshalXMLSignature(valContext);
          certChain = getCertificateChain(signature.getKeyInfo());
          result.setCertChain(certChain);
          

          verifyXMLSignature(signature, valContext);
          


          certVerifier.verifyCertificationChain(null, certChain[0], certChain);
          

          certVerifier.checkRevocationStatus(certChain[0], trustedCerts);
        }
        catch (Exception ex) {
          if ((ex instanceof ITaxSigValidException)) {
            result.setValidStatus(XMLSignatureValidationResult.SIG_STATUS_ERROR);
          } else if ((ex instanceof ITaxCertValidException)) {
            result.setValidStatus(XMLSignatureValidationResult.SIG_STATUS_ERROR);
          } else if ((ex instanceof ITaxStatusValidException)) {
            result.setValidStatus(XMLSignatureValidationResult.SIG_STATUS_WARNING);
          }
          result.setValidMessage(ex.getMessage());
        }
        resultArr.add(result);
      } }
    return resultArr;
  }
  
  private void verifyXMLSignature(XMLSignature signature, DOMValidateContext valContext) throws ITaxSigValidException {
    try {
      boolean coreValidity = signature.validate(valContext);
      

      if (!coreValidity) {
        boolean sv = signature.getSignatureValue().validate(valContext);
        if (!sv) {
          throw new ITaxSigValidException("Chữ ký điện tử trên hồ sơ không hợp lệ");
        }
        
        Iterator ito = signature.getSignedInfo().getReferences().iterator();
        for (int j = 0; ito.hasNext(); j++) {
          boolean refValid = ((Reference)ito.next()).validate(valContext);
          if (!refValid) {
            throw new ITaxSigValidException("Hồ sơ đã bị sửa sau khi ký điện tử");
          }
        }
      }
    } catch (XMLSignatureException ex) {
      throw new ITaxSigValidException("Chữ ký điện tử trên hồ sơ không hợp lệ (" + ex.getMessage() + ").");
    }
  }
  
  private X509Certificate[] getCertificateChain(KeyInfo keyInfo) throws Exception {
    ArrayList certList = new ArrayList();
    if (keyInfo != null) {
      List<XMLStructure> keyInfoContent = keyInfo.getContent();
      for (XMLStructure keyInfoStructure : keyInfoContent) {
        if ((keyInfoStructure instanceof X509Data))
        {

          X509Data x509Data = (X509Data)keyInfoStructure;
          List<Object> x509DataList = x509Data.getContent();
          for (Object x509DataObject : x509DataList) {
            if ((x509DataObject instanceof X509Certificate))
            {

              certList.add(x509DataObject); }
          }
          if (!certList.isEmpty())
            return (X509Certificate[])certList.toArray(new X509Certificate[0]);
        }
      }
    }
    return null;
  }
}
