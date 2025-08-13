package seatechit.tool.taxMessageNtdt;

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

public class DMucTBaoNtdt
{
  private Document dmucDoc;
  private String prefix;
  
  public DMucTBaoNtdt(String xmlFileName)
    throws ParserConfigurationException, SAXException, IOException
  {
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    dbf.setNamespaceAware(true);
    DocumentBuilder db = dbf.newDocumentBuilder();
    dmucDoc = db.parse(new File(xmlFileName));
    prefix = dmucDoc.getDocumentElement().getPrefix();
  }
  
  public String getTBaoViewType(String maTBao, String pbanTBao) {
    return getTBaoAttr(maTBao, pbanTBao, "viewMethod");
  }
  
  public String getTKhaiOrientation(String maTBao, String pbanTBao) { return getTBaoAttr(maTBao, pbanTBao, "orientation"); }
  
  private String getTBaoAttr(String maTBao, String pbanTBao, String attr) {
    String tbaoNodeName = "TBao";
    if (prefix != null) {
      tbaoNodeName = prefix + ":" + tbaoNodeName;
    }
    NodeList nList = dmucDoc.getElementsByTagName(tbaoNodeName);
    for (int temp = 0; temp < nList.getLength(); temp++) {
      Node nNode = nList.item(temp);
      if (nNode.getNodeType() == 1) {
        Element eElement = (Element)nNode;
        if ((maTBao.equals(eElement.getAttribute("maTBao"))) && (pbanTBao.equals(eElement.getAttribute("pbanTBao"))))
        {

          return eElement.getAttribute(attr);
        }
      }
    }
    return null;
  }
  
  public String getXSDTBao(String maTBao, String pbanTBao) { return getTTinTBao(maTBao, pbanTBao, "XMLSchema"); }
  
  public String getXSLTTBao(String maTBao, String pbanTBao) {
    return getTTinTBao(maTBao, pbanTBao, "XSLT");
  }
  
  public String getExcelTemplateTTBao(String maTBao, String pbanTBao) { return getTTinTBao(maTBao, pbanTBao, "ExcelTemplate"); }
  
  private String getTTinTBao(String maTBao, String pbanTBao, String nodeName) {
    String tbaoNodeName = "TBao";
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
        if ((maTBao.equals(eElement.getAttribute("maTBao"))) && 
          (pbanTBao.equals(eElement.getAttribute("pbanTBao"))))
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
  
  public String getPLucViewType(String maTBao, String pbanTBao, String plucID) { return getPLucAttr(maTBao, pbanTBao, plucID, "plucViewMethod"); }
  

  public String getPLucOrientation(String maTBao, String pbanTBao, String plucID) { return getPLucAttr(maTBao, pbanTBao, plucID, "plucOrientation"); }
  
  private String getPLucAttr(String maTBao, String pbanTBao, String plucID, String attr) {
    String tbaoNodeName = "TBao";
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
        if ((maTBao.equals(eElement.getAttribute("maTBao"))) && 
          (pbanTBao.equals(eElement.getAttribute("pbanTBao"))))
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
  
  public String getTenPLuc(String maTBao, String pbanTBao, String plucID) { return getTTinPLuc(maTBao, pbanTBao, plucID, "TenPLuc"); }
  
  public String getXSLTPLuc(String maTBao, String pbanTBao, String plucID) {
    return getTTinPLuc(maTBao, pbanTBao, plucID, "PLucXSLT");
  }
  
  public String getExcelTemplatePLuc(String maTBao, String pbanTBao, String plucID) { return getTTinPLuc(maTBao, pbanTBao, plucID, "PLucExcelTemplate"); }
  
  private String getTTinPLuc(String maTBao, String pbanTBao, String plucID, String nodeName) {
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
        if ((maTBao.equals(eElement.getAttribute("maTBao"))) && 
          (pbanTBao.equals(eElement.getAttribute("pbanTBao"))))
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
