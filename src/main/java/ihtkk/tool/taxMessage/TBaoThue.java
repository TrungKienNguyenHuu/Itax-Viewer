package ihtkk.tool.taxMessage;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import javax.xml.parsers.ParserConfigurationException;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.FilenameUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import ihtkk.tool.ConfigInfo;
import ihtkk.tool.ITaxViewerException;
import ihtkk.tool.signature.IHTKKXMLSignature;
import ihtkk.tool.taxdoc.HSoThue;
import ihtkk.tool.taxdoc.PLuc;


public class TBaoThue
  extends HSoThue
{
  public TBaoThue(Document tkhaiDoc, String tkhaiFileName, ConfigInfo config)
          throws Exception {
    super(tkhaiDoc, tkhaiFileName, config);
    DMucTBao dmTBao = config.getDmTBao();
    String nodeName = null;
    

    if (prefix != null) {
      nodeName = prefix + ":" + "maTBao";
    }
    else {
      nodeName = "maTBao";
    }
    Node node = tkhaiDoc.getElementsByTagName(nodeName).item(0);
    if (node == null) {
      throw new ITaxViewerException("Cấu trúc tệp hồ sơ không đúng: không có thẻ dữ liệu 'maTBao'");
    }
    maHSo = node.getTextContent();
    
    if (prefix != null) {
      nodeName = prefix + ":" + "pbanTBao";
    }
    else {
      nodeName = "pbanTBao";
    }
    node = tkhaiDoc.getElementsByTagName(nodeName).item(0);
    if (node == null) {
      throw new ITaxViewerException("Cấu trúc tệp hồ sơ không đúng: không có thẻ dữ liệu 'pbanTBao'");
    }
    pbanHSoXML = node.getTextContent();
    
    xsdFile = dmTBao.getXSDTBao(maHSo, pbanHSoXML);
    if (xsdFile == null) {
      throw new ITaxViewerException("Mã Thông báo (" + maHSo + ") hoặc phiên bản thông báo (" + pbanHSoXML + ") không đúng");
    }
    
    viewMethod = dmTBao.getTBaoViewType(maHSo, pbanHSoXML);
    
    excelFile = dmTBao.getExcelTemplateTTBao(maHSo, pbanHSoXML);
    
    xsltFile = dmTBao.getXSLTTBao(maHSo, pbanHSoXML);
    
    orientation = dmTBao.getTKhaiOrientation(maHSo, pbanHSoXML);
    
    plucList = getPLucList(dmTBao);
    

    sigValidationResult = new IHTKKXMLSignature(config.getRootCerts(), config.getTrustedCerts()).verifyXMLSignature(tkhaiDoc, config.getTBaoXpath());
    

    hsoViewFileName = createTemFileForView();
  }
  
  private String createTemFileForView() throws ITaxViewerException, IOException
  {
    String defaultNamespace = "xmlns=\"http://kekhaithue.gdt.gov.vn/TBaoThue\"";
    String defaultNamespace1 = "xmlns=\"http://kekhaithue.gdt.gov.vn/TBThue_T-VAN\"";
    String content = FileUtils.readFileToString(new File(hsoFileName), "UTF-8");
    content = content.replaceAll(defaultNamespace, "");
    content = content.replaceAll(defaultNamespace1, "");
    String baseFileName = FilenameUtils.getBaseName(hsoFileName);
    File tempfile = File.createTempFile(baseFileName, ".tmp");
    tempfile.deleteOnExit();
    FileUtils.writeStringToFile(tempfile, content, "UTF-8");
    
    return tempfile.getAbsolutePath();
  }
  
  private Collection getPLucList(DMucTBao dmTBao) { ArrayList collPLuc = new ArrayList();
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
        String plucID; if (plucIDWithPrefix.length == 1) {
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
