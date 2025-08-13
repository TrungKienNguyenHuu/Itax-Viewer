package seatechit.tool.taxCatalog;

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

public class DMucDMuc
{
  private Document dmucDoc;
  private String prefix;
  
  public DMucDMuc(String xmlFileName)
    throws ParserConfigurationException, SAXException, IOException
  {
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    dbf.setNamespaceAware(true);
    DocumentBuilder db = dbf.newDocumentBuilder();
    dmucDoc = db.parse(new File(xmlFileName));
    prefix = dmucDoc.getDocumentElement().getPrefix();
  }
  
  public String getDmucViewType(String maDanhMuc, String pBanDanhMuc) {
    return getDmucAttr(maDanhMuc, pBanDanhMuc, "viewMethod");
  }
  
  public String getDmucOrientation(String maDanhMuc, String pBanDanhMuc) { return getDmucAttr(maDanhMuc, pBanDanhMuc, "orientation"); }
  
  private String getDmucAttr(String maDanhMuc, String pBanDanhMuc, String attr) {
    String tbaoNodeName = "DMuc";
    if (prefix != null) {
      tbaoNodeName = prefix + ":" + tbaoNodeName;
    }
    NodeList nList = dmucDoc.getElementsByTagName(tbaoNodeName);
    for (int temp = 0; temp < nList.getLength(); temp++) {
      Node nNode = nList.item(temp);
      if (nNode.getNodeType() == 1) {
        Element eElement = (Element)nNode;
        if ((maDanhMuc.equals(eElement.getAttribute("maDanhMuc"))) && (pBanDanhMuc.equals(eElement.getAttribute("pBanDanhMuc"))))
        {

          return eElement.getAttribute(attr);
        }
      }
    }
    return null;
  }
  
  public String getXSDDmuc(String maDanhMuc, String pBanDanhMuc) { return getTTinDmuc(maDanhMuc, pBanDanhMuc, "XMLSchema"); }
  
  public String getXSLTDmuc(String maDanhMuc, String pBanDanhMuc) {
    return getTTinDmuc(maDanhMuc, pBanDanhMuc, "XSLT");
  }
  
  public String getExcelTemplateTDmuc(String maDanhMuc, String pBanDanhMuc) { return getTTinDmuc(maDanhMuc, pBanDanhMuc, "ExcelTemplate"); }
  
  private String getTTinDmuc(String maDanhMuc, String pBanDanhMuc, String nodeName) {
    String tbaoNodeName = "DMuc";
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
        if ((maDanhMuc.equals(eElement.getAttribute("maDanhMuc"))) && 
          (pBanDanhMuc.equals(eElement.getAttribute("pBanDanhMuc"))))
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
  
  public String getPLucViewType(String maDanhMuc, String pBanDanhMuc, String plucID) { return getPLucAttr(maDanhMuc, pBanDanhMuc, plucID, "plucViewMethod"); }
  

  public String getPLucOrientation(String maDanhMuc, String pBanDanhMuc, String plucID) { return getPLucAttr(maDanhMuc, pBanDanhMuc, plucID, "plucOrientation"); }
  
  private String getPLucAttr(String maDanhMuc, String pBanDanhMuc, String plucID, String attr) {
    String tbaoNodeName = "DMuc";
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
        if ((maDanhMuc.equals(eElement.getAttribute("maDanhMuc"))) && 
          (pBanDanhMuc.equals(eElement.getAttribute("pBanDanhMuc"))))
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
  
  public String getTenPLuc(String maDanhMuc, String pBanDanhMuc, String plucID) { return getTTinPLuc(maDanhMuc, pBanDanhMuc, plucID, "TenPLuc"); }
  
  public String getXSLTPLuc(String maDanhMuc, String pBanDanhMuc, String plucID) {
    return getTTinPLuc(maDanhMuc, pBanDanhMuc, plucID, "PLucXSLT");
  }
  
  public String getExcelTemplatePLuc(String maDanhMuc, String pBanDanhMuc, String plucID) { return getTTinPLuc(maDanhMuc, pBanDanhMuc, plucID, "PLucExcelTemplate"); }
  
  private String getTTinPLuc(String maDanhMuc, String pBanDanhMuc, String plucID, String nodeName) {
    String tbaoNodeName = "DMuc";
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
        if ((maDanhMuc.equals(eElement.getAttribute("maDanhMuc"))) && 
          (pBanDanhMuc.equals(eElement.getAttribute("pBanDanhMuc"))))
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
