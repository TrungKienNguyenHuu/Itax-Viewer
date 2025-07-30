package ihtkk.tool.taxvoucher;

import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import ihtkk.tool.ConfigInfo;
import ihtkk.tool.ITaxViewerException;
import ihtkk.tool.signature.IHTKKXMLSignature;
import ihtkk.tool.taxdoc.HSoThue;

public class GNTNSNN extends HSoThue
{
  public GNTNSNN(Document ctuDoc, String ctuFileName, ConfigInfo config) throws java.io.IOException, javax.xml.parsers.ParserConfigurationException, ITaxViewerException
  {
    super(ctuDoc, ctuFileName, config);
    DMucCTu dmCTu = config.getDmCTu();
    String nodeName = null;
    

    if (prefix != null) {
      nodeName = prefix + ":" + "MA_CTU";
    }
    else {
      nodeName = "MA_CTU";
    }
    Node node = ctuDoc.getElementsByTagName(nodeName).item(0);
    if (node == null) {
      throw new ITaxViewerException("Cấu trúc tệp hồ sơ không đúng: không có thẻ dữ liệu 'MA_CTU'");
    }
    maHSo = node.getTextContent();
    
    if (prefix != null) {
      nodeName = prefix + ":" + "PBAN_TLIEU_XML";
    }
    else {
      nodeName = "PBAN_TLIEU_XML";
    }
    node = ctuDoc.getElementsByTagName(nodeName).item(0);
    if (node == null)
    {
      pbanHSoXML = "1.0";
    } else {
      pbanHSoXML = node.getTextContent();
    }
    
    xsdFile = dmCTu.getXSDCTu(maHSo, pbanHSoXML);
    if (xsdFile == null) {
      throw new ITaxViewerException("Mã hồ sơ (" + maHSo + ") hoặc phiên bản hồ sơ (" + pbanHSoXML + ") không đúng");
    }
    










    viewMethod = dmCTu.getCTuViewType(maHSo, pbanHSoXML);
    xsltFile = dmCTu.getXSLTCTu(maHSo, pbanHSoXML);
    

    sigValidationResult = new IHTKKXMLSignature(config.getRootCerts(), config.getTrustedCerts()).verifyXMLSignature(ctuDoc);
    hsoViewFileName = ctuFileName;
  }
}
