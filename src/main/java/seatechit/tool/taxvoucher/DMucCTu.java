package seatechit.tool.taxvoucher;

import java.io.File;
import java.io.IOException;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

public class DMucCTu
{
  private Document dmucDoc;
  private String prefix;
  
  public DMucCTu(String xmlFileName)
    throws ParserConfigurationException, SAXException, IOException
  {
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    dbf.setNamespaceAware(true);
    DocumentBuilder db = dbf.newDocumentBuilder();
    dmucDoc = db.parse(new File(xmlFileName));
    prefix = dmucDoc.getDocumentElement().getPrefix();
  }
  
  public String getCTuViewType(String maCTu, String pbanCTu) {
    String tkhaiNodeName = "CTu";
    if (prefix != null) {
      tkhaiNodeName = prefix + ":" + tkhaiNodeName;
    }
    NodeList nList = dmucDoc.getElementsByTagName(tkhaiNodeName);
    for (int temp = 0; temp < nList.getLength(); temp++) {
      Node nNode = nList.item(temp);
      if (nNode.getNodeType() == 1) {
        Element eElement = (Element)nNode;
        if ((maCTu.equals(eElement.getAttribute("maCTu"))) && (pbanCTu.equals(eElement.getAttribute("pbanCTu"))))
        {
          return eElement.getAttribute("viewMethod");
        }
      }
    }
    return null;
  }
  
  public String getXSDCTu(String maCTu, String pbanCTu) { return getTTinCTu(maCTu, pbanCTu, "XMLSchema"); }
  
  public String getXSLTCTu(String maCTu, String pbanCTu) {
    return getTTinCTu(maCTu, pbanCTu, "XSLT");
  }
  
  public String getExcelTemplateCTu(String maCTu, String pbanCTu) { return getTTinCTu(maCTu, pbanCTu, "ExcelTemplate"); }
  
  private String getTTinCTu(String maCTu, String pbanCTu, String nodeName) {
    String tkhaiNodeName = "CTu";
    if (prefix != null) {
      tkhaiNodeName = prefix + ":" + tkhaiNodeName;
    }
    if (prefix != null) {
      nodeName = prefix + ":" + nodeName;
    }
    NodeList nList = dmucDoc.getElementsByTagName(tkhaiNodeName);
    for (int temp = 0; temp < nList.getLength(); temp++) {
      Node nNode = nList.item(temp);
      if (nNode.getNodeType() == 1) {
        Element eElement = (Element)nNode;
        if ((maCTu.equals(eElement.getAttribute("maCTu"))) && 
          (pbanCTu.equals(eElement.getAttribute("pbanCTu")))) {
          for (Node child = eElement.getFirstChild(); child != null; child = child.getNextSibling()) {
            if (((child instanceof Element)) && (nodeName.equals(child.getNodeName()))) {
              return child.getTextContent();
            }
          }
          return null;
        }
      }
    }
    return null;
  }
}
