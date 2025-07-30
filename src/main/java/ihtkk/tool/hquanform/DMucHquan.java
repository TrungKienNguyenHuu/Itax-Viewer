package ihtkk.tool.hquanform;

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

public class DMucHquan
{
  private Document dmucDoc;
  private String prefix;
  
  public DMucHquan(String xmlFileName)
    throws ParserConfigurationException, SAXException, IOException
  {
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    dbf.setNamespaceAware(true);
    DocumentBuilder db = dbf.newDocumentBuilder();
    dmucDoc = db.parse(new File(xmlFileName));
    prefix = dmucDoc.getDocumentElement().getPrefix();
  }
  
  public String getTBaoViewType(String maTBaoHquan, String pbanTBaoHquan) {
    return getTBaoAttr(maTBaoHquan, pbanTBaoHquan, "viewMethod");
  }
  
  public String getTKhaiOrientation(String maTBaoHquan, String pbanTBaoHquan) { return getTBaoAttr(maTBaoHquan, pbanTBaoHquan, "orientation"); }
  
  private String getTBaoAttr(String maTBaoHquan, String pbanTBaoHquan, String attr) {
    String tbaoNodeName = "TBaoHquan";
    if (prefix != null) {
      tbaoNodeName = prefix + ":" + tbaoNodeName;
    }
    NodeList nList = dmucDoc.getElementsByTagName(tbaoNodeName);
    for (int temp = 0; temp < nList.getLength(); temp++) {
      Node nNode = nList.item(temp);
      if (nNode.getNodeType() == 1) {
        Element eElement = (Element)nNode;
        if ((maTBaoHquan.equals(eElement.getAttribute("maTBaoHquan"))) && (pbanTBaoHquan.equals(eElement.getAttribute("pbanTBaoHquan"))))
        {

          return eElement.getAttribute(attr);
        }
      }
    }
    return null;
  }
  
  public String getXSDTBao(String maTBaoHquan, String pbanTBaoHquan) { return getTTinTBao(maTBaoHquan, pbanTBaoHquan, "XMLSchema"); }
  
  public String getXSLTTBao(String maTBaoHquan, String pbanTBaoHquan) {
    return getTTinTBao(maTBaoHquan, pbanTBaoHquan, "XSLT");
  }
  
  public String getExcelTemplateTTBao(String maTBaoHquan, String pbanTBaoHquan) { return getTTinTBao(maTBaoHquan, pbanTBaoHquan, "ExcelTemplate"); }
  
  private String getTTinTBao(String maTBaoHquan, String pbanTBaoHquan, String nodeName) {
    String tbaoNodeName = "TBaoHquan";
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
        if ((maTBaoHquan.equals(eElement.getAttribute("maTBaoHquan"))) && 
          (pbanTBaoHquan.equals(eElement.getAttribute("pbanTBaoHquan"))))
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
  
  public String getPLucViewType(String maTBaoHquan, String pbanTBaoHquan, String plucID) { return getPLucAttr(maTBaoHquan, pbanTBaoHquan, plucID, "plucViewMethod"); }
  

  public String getPLucOrientation(String maTBaoHquan, String pbanTBaoHquan, String plucID) { return getPLucAttr(maTBaoHquan, pbanTBaoHquan, plucID, "plucOrientation"); }
  
  private String getPLucAttr(String maTBaoHquan, String pbanTBaoHquan, String plucID, String attr) {
    String tbaoNodeName = "TBaoHquan";
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
        if ((maTBaoHquan.equals(eElement.getAttribute("maTBaoHquan"))) && 
          (maTBaoHquan.equals(eElement.getAttribute("pbanTBaoHquan"))))
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
  
  public String getTenPLuc(String maTBaoHquan, String pbanTBaoHquan, String plucID) { return getTTinPLuc(maTBaoHquan, pbanTBaoHquan, plucID, "TenPLuc"); }
  
  public String getXSLTPLuc(String maTBaoHquan, String pbanTBaoHquan, String plucID) {
    return getTTinPLuc(maTBaoHquan, pbanTBaoHquan, plucID, "PLucXSLT");
  }
  
  public String getExcelTemplatePLuc(String maTBaoHquan, String pbanTBaoHquan, String plucID) { return getTTinPLuc(maTBaoHquan, pbanTBaoHquan, plucID, "PLucExcelTemplate"); }
  
  private String getTTinPLuc(String maTBaoHquan, String pbanTBaoHquan, String plucID, String nodeName) {
    String tbaoNodeName = "TBaoHquan";
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
        if ((maTBaoHquan.equals(eElement.getAttribute("maTBaoHquan"))) && 
          (pbanTBaoHquan.equals(eElement.getAttribute("pbanTBaoHquan"))))
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
