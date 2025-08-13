package seatechit.tool.taxCatalog;

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
import seatechit.tool.ConfigInfo;
import seatechit.tool.ITaxViewerException;
import seatechit.tool.signature.IHTKKXMLSignature;
import seatechit.tool.taxdoc.HSoThue;
import seatechit.tool.taxdoc.PLuc;



public class DMuc
  extends HSoThue
{
  public DMuc(Document tkhaiDoc, String tkhaiFileName, ConfigInfo config)
    throws IOException, ParserConfigurationException, ITaxViewerException
  {
    super(tkhaiDoc, tkhaiFileName, config);
    DMucDMuc dmDMuc = config.getDmDMuc();
    String nodeName = null;
    

    if (prefix != null) {
      nodeName = prefix + ":" + "maDanhMuc";
    }
    else {
      nodeName = "maDanhMuc";
    }
    Node node = tkhaiDoc.getElementsByTagName(nodeName).item(0);
    if (node == null) {
      throw new ITaxViewerException("Cấu trúc tệp hồ sơ không đúng: không có thẻ dữ liệu 'maDanhMuc'");
    }
    maHSo = node.getTextContent();
    
    if (prefix != null) {
      nodeName = prefix + ":" + "pBanDanhMuc";
    }
    else {
      nodeName = "pBanDanhMuc";
    }
    node = tkhaiDoc.getElementsByTagName(nodeName).item(0);
    if (node == null) {
      throw new ITaxViewerException("Cấu trúc tệp hồ sơ không đúng: không có thẻ dữ liệu 'pBanDanhMuc'");
    }
    pbanHSoXML = node.getTextContent();
    
    xsdFile = dmDMuc.getXSDDmuc(maHSo, pbanHSoXML);
    if (xsdFile == null) {
      throw new ITaxViewerException("Mã Danh mục (" + maHSo + ") hoặc phiên bản Danh mục (" + pbanHSoXML + ") không đúng");
    }
    
    viewMethod = dmDMuc.getDmucViewType(maHSo, pbanHSoXML);
    
    excelFile = dmDMuc.getExcelTemplateTDmuc(maHSo, pbanHSoXML);
    
    xsltFile = dmDMuc.getXSLTDmuc(maHSo, pbanHSoXML);
    
    orientation = dmDMuc.getDmucOrientation(maHSo, pbanHSoXML);
    
    plucList = getPLucList(dmDMuc);
    

    sigValidationResult = new IHTKKXMLSignature(config.getRootCerts(), config.getTrustedCerts()).verifyXMLSignature(tkhaiDoc, config.getDmucXpath());
    

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
  
  private Collection getPLucList(DMucDMuc dmDmuc) { ArrayList collPLuc = new ArrayList();
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
        pluc.setPlucName(dmDmuc.getTenPLuc(maHSo, pbanHSoXML, plucID));
        pluc.setPlucViewMethod(dmDmuc.getPLucViewType(maHSo, pbanHSoXML, plucID));
        pluc.setOrientation(dmDmuc.getPLucOrientation(maHSo, pbanHSoXML, plucID));
        pluc.setPlucExcelFile(dmDmuc.getExcelTemplatePLuc(maHSo, pbanHSoXML, plucID));
        pluc.setPlucXSLTFile(dmDmuc.getXSLTPLuc(maHSo, pbanHSoXML, plucID));
        
        collPLuc.add(pluc);
      }
    }
    return collPLuc;
  }
}
