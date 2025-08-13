package seatechit.tool.hquanform1;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import javax.xml.parsers.ParserConfigurationException;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.FilenameUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import seatechit.tool.ConfigInfo;
import seatechit.tool.ITaxViewerException;
import seatechit.tool.signature.IHTKKXMLSignature;
import seatechit.tool.signature.XMLSignatureValidationResult;
import seatechit.tool.taxdoc.HSoThue;
import seatechit.tool.taxdoc.PLuc;



public class HquanForm1
  extends HSoThue
{
  public HquanForm1(Document tkhaiDoc, String tkhaiFileName, ConfigInfo config)
    throws IOException, ParserConfigurationException, ITaxViewerException
  {
    super(tkhaiDoc, tkhaiFileName, config);
    DMucHquan1 dmucHquan = config.getDmHquan1();
    String nodeName = null;
    

    if (prefix != null) {
      nodeName = prefix + ":" + "MA_LH_XNK";
    }
    else {
      nodeName = "MA_LH_XNK";
    }
    Node node = tkhaiDoc.getElementsByTagName(nodeName).item(0);
    if (node == null) {
      throw new ITaxViewerException("Cấu trúc tệp hồ sơ không đúng: không có thẻ dữ liệu 'MA_LH_XNK'");
    }
    maHSo = node.getTextContent();
    
    if (prefix != null) {
      nodeName = prefix + ":" + "PBAN_XML";
    }
    else {
      nodeName = "PBAN_XML";
    }
    node = tkhaiDoc.getElementsByTagName(nodeName).item(0);
    if (node == null)
    {
      pbanHSoXML = "1.0.0";
    }
    if (node != null)
    {
      pbanHSoXML = node.getTextContent();
    }
    xsdFile = dmucHquan.getXSDTBao(maHSo, pbanHSoXML);
    if (xsdFile == null) {
      throw new ITaxViewerException("Mã Thông báo (" + maHSo + ") hoặc phiên bản thông báo (" + pbanHSoXML + ") không đúng");
    }
    
    viewMethod = dmucHquan.getTBaoViewType(maHSo, pbanHSoXML);
    
    excelFile = dmucHquan.getExcelTemplateTTBao(maHSo, pbanHSoXML);
    
    xsltFile = dmucHquan.getXSLTTBao(maHSo, pbanHSoXML);
    
    orientation = dmucHquan.getTKhaiOrientation(maHSo, pbanHSoXML);
    
    plucList = getPLucList(dmucHquan);
    

    sigValidationResult = new IHTKKXMLSignature(config.getRootCerts(), config.getTrustedCerts()).verifyXMLSignature(tkhaiDoc);
    
    Iterator ito = sigValidationResult.iterator();
    
    ArrayList resultArr = new ArrayList();
    while (ito.hasNext())
    {
      XMLSignatureValidationResult valResult = (XMLSignatureValidationResult)ito.next();
      valResult.setValidStatus(XMLSignatureValidationResult.SIG_STATUS_GOOD);
      resultArr.add(valResult);
    }
    
    sigValidationResult = resultArr;
    
    hsoViewFileName = createTemFileForView();
  }
  
  private String createTemFileForView() throws ITaxViewerException, IOException
  {
    String defaultNamespace = "xmlns=\"http://kekhaithue.gdt.gov.vn/TKhaiThue\"";
    String content = FileUtils.readFileToString(new File(hsoFileName), "UTF-8");
    content = content.replaceAll(defaultNamespace, "");
    
    String baseFileName = FilenameUtils.getBaseName(hsoFileName);
    File tempfile = File.createTempFile(baseFileName, ".tmp");
    tempfile.deleteOnExit();
    FileUtils.writeStringToFile(tempfile, content, "UTF-8");
    
    return tempfile.getAbsolutePath();
  }
  
  private Collection getPLucList(DMucHquan1 dmTBao) { ArrayList collPLuc = new ArrayList();
    String plucNodeName = "PLuc";
    if (prefix != null) {
      plucNodeName = prefix + ":" + plucNodeName;
    }
    
    Node plucNode = tkhaiDoc.getElementsByTagName(plucNodeName).item(0);
    if (plucNode == null) {
      return null;
    }
    NodeList plucList = plucNode.getChildNodes();
    int len = plucList.getLength();
    for (int i = 0; i < len; i++) {
      if (plucList.item(i).getNodeType() == 1) {
        PLuc pluc = new PLuc();
        String[] plucIDWithPrefix = plucList.item(i).getNodeName().split(":");
        String plucID;
        if (plucIDWithPrefix.length == 1) {
          plucID = plucIDWithPrefix[0];
        } else {
          plucID = plucIDWithPrefix[1];
        }
        pluc.setPlucID(plucID);
        pluc.setPlucName(dmTBao.getTenPLuc(maHSo, pbanHSoXML, plucID));
        pluc.setPlucViewMethod(dmTBao.getPLucViewType(maHSo, pbanHSoXML, plucID));
        pluc.setOrientation(dmTBao.getPLucOrientation(maHSo, pbanHSoXML, plucID));
        pluc.setPlucExcelFile(dmTBao.getExcelTemplatePLuc(maHSo, pbanHSoXML, plucID));
        pluc.setPlucXSLTFile(dmTBao.getXSLTPLuc(maHSo, pbanHSoXML, plucID));
        
        collPLuc.add(pluc);
      }
    }
    return collPLuc;
  }
}
