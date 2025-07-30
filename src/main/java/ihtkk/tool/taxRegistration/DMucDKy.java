package ihtkk.tool.taxRegistration;

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


public class DMucDKy
{
  private Document dmucDoc;
  private String prefix;
  
  public DMucDKy(String xmlFileName)
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
  
  private String getTBaoAttr(String maDKy, String pBanDKy, String attr) {
    String tbaoNodeName = "DKyThueDTu";
    if (prefix != null) {
      tbaoNodeName = prefix + ":" + tbaoNodeName;
    }
    NodeList nList = dmucDoc.getElementsByTagName(tbaoNodeName);
    for (int temp = 0; temp < nList.getLength(); temp++) {
      Node nNode = nList.item(temp);
      if (nNode.getNodeType() == 1) {
        Element eElement = (Element)nNode;
        if ((maDKy.equals(eElement.getAttribute("maDKy"))) && (pBanDKy.equals(eElement.getAttribute("pBanDKy"))))
        {

          return eElement.getAttribute(attr);
        }
      }
    }
    return null;
  }
  
  public String getXSDTBao(String maDKy, String pBanDKy) { return getTTinTBao(maDKy, pBanDKy, "XMLSchema"); }
  
  public String getXSLTTBao(String maDKy, String pBanDKy) {
    return getTTinTBao(maDKy, pBanDKy, "XSLT");
  }
  
  public String getExcelTemplateTTBao(String maDKy, String pBanDKy) { return getTTinTBao(maDKy, pBanDKy, "ExcelTemplate"); }
  
  private String getTTinTBao(String maDKy, String pBanDKy, String nodeName) {
    String tbaoNodeName = "DKyThueDTu";
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
        if ((maDKy.equals(eElement.getAttribute("maDKy"))) && 
          (pBanDKy.equals(eElement.getAttribute("pBanDKy"))))
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
  
  public String getPLucViewType(String maDKy, String pBanDKy, String plucID) { return getPLucAttr(maDKy, pBanDKy, plucID, "plucViewMethod"); }
  

  public String getPLucOrientation(String maDKy, String pBanDKy, String plucID) { return getPLucAttr(maDKy, pBanDKy, plucID, "plucOrientation"); }
  
  private String getPLucAttr(String maDKy, String pBanDKy, String plucID, String attr) {
    String tbaoNodeName = "DKyThueDTu";
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
        if ((maDKy.equals(eElement.getAttribute("maDKy"))) && 
          (pBanDKy.equals(eElement.getAttribute("pBanDKy"))))
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
  
  public String getTenPLuc(String maDKy, String pBanDKy, String plucID) { return getTTinPLuc(maDKy, pBanDKy, plucID, "TenPLuc"); }
  
  public String getXSLTPLuc(String maDKy, String pBanDKy, String plucID) {
    return getTTinPLuc(maDKy, pBanDKy, plucID, "PLucXSLT");
  }
  
  public String getExcelTemplatePLuc(String maDKy, String pBanDKy, String plucID) { return getTTinPLuc(maDKy, pBanDKy, plucID, "PLucExcelTemplate"); }
  
  private String getTTinPLuc(String maDKy, String pBanDKy, String plucID, String nodeName) {
    String tbaoNodeName = "DKyThueDTu";
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
        if ((maDKy.equals(eElement.getAttribute("maDKy"))) && 
          (pBanDKy.equals(eElement.getAttribute("pBanDKy"))))
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
