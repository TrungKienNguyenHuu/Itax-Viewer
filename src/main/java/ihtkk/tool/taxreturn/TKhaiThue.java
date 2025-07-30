package ihtkk.tool.taxreturn;

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


public class TKhaiThue
  extends HSoThue
{
  public TKhaiThue(Document tkhaiDoc, String tkhaiFileName, ConfigInfo config)
    throws IOException, ParserConfigurationException, ITaxViewerException
  {
    super(tkhaiDoc, tkhaiFileName, config);
    DMucTKhai dmTKhai = config.getDmTKhai();
    String nodeName = null;
    

    if (prefix != null) {
      nodeName = prefix + ":" + "maTKhai";
    }
    else {
      nodeName = "maTKhai";
    }
    Node node = tkhaiDoc.getElementsByTagName(nodeName).item(0);
    if (node == null) {
      throw new ITaxViewerException("Cấu trúc tệp hồ sơ không đúng: không có thẻ dữ liệu 'maTKhai'");
    }
    maHSo = node.getTextContent();
    
    if (prefix != null) {
      nodeName = prefix + ":" + "pbanTKhaiXML";
    }
    else {
      nodeName = "pbanTKhaiXML";
    }
    node = tkhaiDoc.getElementsByTagName(nodeName).item(0);
    if (node == null) {
      throw new ITaxViewerException("Cấu trúc tệp hồ sơ không đúng: không có thẻ dữ liệu 'pbanTKhaiXML'");
    }
    pbanHSoXML = node.getTextContent();
    
    if ((maHSo.equals("42")) || (maHSo.equals("43")) || (maHSo.equals("44")) || (maHSo.equals("103")))
    {
      if ((!pbanHSoXML.equals("2.0.5")) && 
        (!pbanHSoXML.equals("2.0.8")))
      {
        pbanHSoXML = "2.0.0";
      }
    }
    

    if (!maHSo.equals("680")) {
      if (prefix != null) {
        nodeName = prefix + ":" + "loaiTKhai";
      }
      else {
        nodeName = "loaiTKhai";
      }
      node = tkhaiDoc.getElementsByTagName(nodeName).item(0);
      if (node == null) {
        throw new ITaxViewerException("Cấu trúc tệp hồ sơ không đúng: không có thẻ dữ liệu 'loaiTKhai'");
      }
      loaiHSo = node.getTextContent();
    }
    

    if (prefix != null) {
      nodeName = prefix + ":" + "tenTKhai";
    } else {
      nodeName = "tenTKhai";
    }
    node = tkhaiDoc.getElementsByTagName(nodeName).item(0);
    if (node == null) {
      throw new ITaxViewerException("Cấu trúc tệp hồ sơ không đúng: không có thẻ dữ liệu 'tenTKhai'");
    }
    tenHSo = node.getTextContent();
    if (!maHSo.equals("680")) {
      if (prefix != null) {
        nodeName = prefix + ":" + "kieuKy";
      } else {
        nodeName = "kieuKy";
      }
      
      node = tkhaiDoc.getElementsByTagName(nodeName).item(0);
      if (node == null) {
        throw new ITaxViewerException("Cấu trúc tệp hồ sơ không đúng: không có thẻ dữ liệu 'kieuKy'");
      }
    }
    

    if ((maHSo.equals("680")) && ((loaiHSo == null) || (loaiHSo.equals("")))) {
      loaiHSo = "C";
    }
    xsdFile = dmTKhai.getXSDTKhai(maHSo, pbanHSoXML, loaiHSo);
    if (xsdFile == null) {
      throw new ITaxViewerException("Mã hồ sơ (" + maHSo + ") hoặc phiên bản hồ sơ (" + pbanHSoXML + ") không đúng");
    }
    










    viewMethod = dmTKhai.getTKhaiViewType(maHSo, pbanHSoXML, loaiHSo);
    
    excelFile = dmTKhai.getExcelTemplateTTKhai(maHSo, pbanHSoXML, loaiHSo);
    
    xsltFile = dmTKhai.getXSLTTKhai(maHSo, pbanHSoXML, loaiHSo);
    
    orientation = dmTKhai.getTKhaiOrientation(maHSo, pbanHSoXML, loaiHSo);
    
    plucList = getPLucList(dmTKhai);
    

    sigValidationResult = new IHTKKXMLSignature(config.getRootCerts(), config.getTrustedCerts()).verifyXMLSignature(tkhaiDoc);
    

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
  
  private Collection getPLucList(DMucTKhai dmTKhai) { ArrayList collPLuc = new ArrayList();
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
        pluc.setPlucName(dmTKhai.getTenPLuc(maHSo, pbanHSoXML, loaiHSo, plucID));
        pluc.setPlucViewMethod(dmTKhai.getPLucViewType(maHSo, pbanHSoXML, loaiHSo, plucID));
        pluc.setOrientation(dmTKhai.getPLucOrientation(maHSo, pbanHSoXML, loaiHSo, plucID));
        pluc.setPlucExcelFile(dmTKhai.getExcelTemplatePLuc(maHSo, pbanHSoXML, loaiHSo, plucID));
        pluc.setPlucXSLTFile(dmTKhai.getXSLTPLuc(maHSo, pbanHSoXML, loaiHSo, plucID));
        
        collPLuc.add(pluc);
      }
    }
    return collPLuc;
  }
}
