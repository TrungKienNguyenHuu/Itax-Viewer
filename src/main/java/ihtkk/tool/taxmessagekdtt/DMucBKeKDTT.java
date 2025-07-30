package ihtkk.tool.taxmessagekdtt;

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

public class DMucBKeKDTT
{
  private Document dmucDoc;
  private String prefix;
  
  public DMucBKeKDTT(String xmlFileName)
    throws ParserConfigurationException, SAXException, IOException
  {
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    dbf.setNamespaceAware(true);
    DocumentBuilder db = dbf.newDocumentBuilder();
    dmucDoc = db.parse(new File(xmlFileName));
    prefix = dmucDoc.getDocumentElement().getPrefix();
  }
  
  public String getTBaoViewType(String maBKe, String pbanBKe) {
    return getTBaoAttr(maBKe, pbanBKe, "viewMethod");
  }
  
  public String getTKhaiOrientation(String maBKe, String pbanBKe) { return getTBaoAttr(maBKe, pbanBKe, "orientation"); }
  
  private String getTBaoAttr(String maBKe, String pbanBKe, String attr) {
    String tbaoNodeName = "BKe";
    if (prefix != null) {
      tbaoNodeName = prefix + ":" + tbaoNodeName;
    }
    NodeList nList = dmucDoc.getElementsByTagName(tbaoNodeName);
    for (int temp = 0; temp < nList.getLength(); temp++) {
      Node nNode = nList.item(temp);
      if (nNode.getNodeType() == 1) {
        Element eElement = (Element)nNode;
        if ((maBKe.equals(eElement.getAttribute("maBKe"))) && (pbanBKe.equals(eElement.getAttribute("pbanBKe"))))
        {

          return eElement.getAttribute(attr);
        }
      }
    }
    return null;
  }
  
  public String getXSDTBao(String maBKe, String pbanBKe) { return getTTinTBao(maBKe, pbanBKe, "XMLSchema"); }
  
  public String getXSLTTBao(String maBKe, String pbanBKe) {
    return getTTinTBao(maBKe, pbanBKe, "XSLT");
  }
  
  public String getExcelTemplateTTBao(String maBKe, String pbanBKe) { return getTTinTBao(maBKe, pbanBKe, "ExcelTemplate"); }
  
  private String getTTinTBao(String maBKe, String pbanBKe, String nodeName) {
    String tbaoNodeName = "BKe";
    if (prefix != null) {
      tbaoNodeName = prefix + ":" + tbaoNodeName;
    }
    if (prefix != null) {
      nodeName = prefix + ":" + nodeName;
    }
    NodeList nList = dmucDoc.getElementsByTagName(tbaoNodeName);
    for (int temp = 0; temp < nList.getLength(); temp++) {
      Node nNode = nList.item(temp);
      if (nNode.getNodeType() == 1) {
        Element eElement = (Element)nNode;
        if ((maBKe.equals(eElement.getAttribute("maBKe"))) && 
          (pbanBKe.equals(eElement.getAttribute("pbanBKe"))))
        {
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
  
  public String getPLucViewType(String maBKe, String pbanBKe, String plucID) { return getPLucAttr(maBKe, pbanBKe, plucID, "plucViewMethod"); }
  

  public String getPLucOrientation(String maBKe, String pbanBKe, String plucID) { return getPLucAttr(maBKe, pbanBKe, plucID, "plucOrientation"); }
  
  private String getPLucAttr(String maBKe, String pbanBKe, String plucID, String attr) {
    String tbaoNodeName = "maBKe";
    if (prefix != null) {
      tbaoNodeName = prefix + ":" + tbaoNodeName;
    }
    String dsPLucNodeName = "DSachPLuc";
    if (prefix != null) {
      dsPLucNodeName = prefix + ":" + dsPLucNodeName;
    }
    NodeList nList = dmucDoc.getElementsByTagName(tbaoNodeName);
    for (int temp = 0; temp < nList.getLength(); temp++) {
      Node nNode = nList.item(temp);
      if (nNode.getNodeType() == 1) {
        Element eElement = (Element)nNode;
        if ((maBKe.equals(eElement.getAttribute("maBKe"))) && 
          (pbanBKe.equals(eElement.getAttribute("pbanBKe"))))
        {
          for (Node child = eElement.getFirstChild(); child != null; child = child.getNextSibling()) {
            if (((child instanceof Element)) && (dsPLucNodeName.equals(child.getNodeName()))) {
              NodeList plList = child.getChildNodes();
              for (int temp1 = 0; temp1 < plList.getLength(); temp1++) {
                Node plucNode = plList.item(temp1);
                if (plucNode.getNodeType() == 1) {
                  Element plucElement = (Element)plucNode;
                  if (plucID.equals(plucElement.getAttribute("plucID"))) {
                    return plucElement.getAttribute(attr);
                  }
                }
              }
              return null;
            }
          }
          return null;
        }
      }
    }
    return null;
  }
  
  public String getTenPLuc(String maBKe, String pbanBKe, String plucID) { return getTTinPLuc(maBKe, pbanBKe, plucID, "TenPLuc"); }
  
  public String getXSLTPLuc(String maBKe, String pbanBKe, String plucID) {
    return getTTinPLuc(maBKe, pbanBKe, plucID, "PLucXSLT");
  }
  
  public String getExcelTemplatePLuc(String maBKe, String pbanBKe, String plucID) { return getTTinPLuc(maBKe, pbanBKe, plucID, "PLucExcelTemplate"); }
  
  private String getTTinPLuc(String maBKe, String pbanBKe, String plucID, String nodeName) {
    String tbaoNodeName = "TBao";
    if (prefix != null) {
      tbaoNodeName = prefix + ":" + tbaoNodeName;
    }
    String dsPLucNodeName = "DSachPLuc";
    if (prefix != null) {
      nodeName = prefix + ":" + nodeName;
    }
    NodeList nList = dmucDoc.getElementsByTagName(tbaoNodeName);
    for (int temp = 0; temp < nList.getLength(); temp++) {
      Node nNode = nList.item(temp);
      if (nNode.getNodeType() == 1) {
        Element eElement = (Element)nNode;
        if ((maBKe.equals(eElement.getAttribute("maBKe"))) && 
          (pbanBKe.equals(eElement.getAttribute("pbanBKe"))))
        {
          for (Node plucChild = eElement.getFirstChild(); plucChild != null; plucChild = plucChild.getNextSibling()) {
            if (((plucChild instanceof Element)) && (dsPLucNodeName.equals(plucChild.getNodeName()))) {
              NodeList plList = plucChild.getChildNodes();
              for (int temp1 = 0; temp1 < plList.getLength(); temp1++) {
                Node plucNode = plList.item(temp1);
                if (plucNode.getNodeType() == 1) {
                  Element plucElement = (Element)plucNode;
                  if (plucID.equals(plucElement.getAttribute("plucID"))) {
                    for (Node child = plucElement.getFirstChild(); child != null; child = child.getNextSibling()) {
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
          return null;
        }
      }
    }
    return null;
  }
}
