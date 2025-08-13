package seatechit.tool.taxreturn;

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

public class DMucTKhai
{
  private Document dmucDoc;
  private String prefix;
  
  public DMucTKhai(String xmlFileName)
    throws ParserConfigurationException, SAXException, IOException
  {
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    dbf.setNamespaceAware(true);
    DocumentBuilder db = dbf.newDocumentBuilder();
    dmucDoc = db.parse(new File(xmlFileName));
    prefix = dmucDoc.getDocumentElement().getPrefix();
  }
  
  public String getTKhaiViewType(String maTKhai, String pbanTKhai, String loaiTKhai) {
    return getTKhaiAttr(maTKhai, pbanTKhai, loaiTKhai, "viewMethod");
  }
  
  public String getTKhaiOrientation(String maTKhai, String pbanTKhai, String loaiTKhai) { return getTKhaiAttr(maTKhai, pbanTKhai, loaiTKhai, "orientation"); }
  
  private String getTKhaiAttr(String maTKhai, String pbanTKhai, String loaiTKhai, String attr) {
    String tkhaiNodeName = "TKhai";
    if (prefix != null) {
      tkhaiNodeName = prefix + ":" + tkhaiNodeName;
    }
    NodeList nList = dmucDoc.getElementsByTagName(tkhaiNodeName);
    for (int temp = 0; temp < nList.getLength(); temp++) {
      Node nNode = nList.item(temp);
      if (nNode.getNodeType() == 1) {
        Element eElement = (Element)nNode;
        if ((maTKhai.equals(eElement.getAttribute("maTKhai"))) && (pbanTKhai.equals(eElement.getAttribute("pbanTKhai"))) && 
          (loaiTKhai.equals(eElement.getAttribute("loaiTKhai"))))
        {
          return eElement.getAttribute(attr);
        }
      }
    }
    return null;
  }
  
  public String getXSDTKhai(String maTKhai, String pbanTKhai, String loaiTKhai) {
    return getTTinTKhai(maTKhai, pbanTKhai, loaiTKhai, "XMLSchema");
  }
  
  public String getXSLTTKhai(String maTKhai, String pbanTKhai, String loaiTKhai) {
    return getTTinTKhai(maTKhai, pbanTKhai, loaiTKhai, "XSLT");
  }
  
  public String getExcelTemplateTTKhai(String maTKhai, String pbanTKhai, String loaiTKhai) {
    return getTTinTKhai(maTKhai, pbanTKhai, loaiTKhai, "ExcelTemplate");
  }
  
  private String getTTinTKhai(String maTKhai, String pbanTKhai, String loaiTKhai, String nodeName) {
    String tkhaiNodeName = "TKhai";
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
        if ((maTKhai.equals(eElement.getAttribute("maTKhai"))) && 
          (pbanTKhai.equals(eElement.getAttribute("pbanTKhai"))) && 
          (loaiTKhai.equals(eElement.getAttribute("loaiTKhai")))) {
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
  
  public String getPLucViewType(String maTKhai, String pbanTKhai, String loaiTKhai, String plucID) {
    return getPLucAttr(maTKhai, pbanTKhai, loaiTKhai, plucID, "plucViewMethod");
  }
  

  public String getPLucOrientation(String maTKhai, String pbanTKhai, String loaiTKhai, String plucID) {
    return getPLucAttr(maTKhai, pbanTKhai, loaiTKhai, plucID, "plucOrientation");
  }
  
  private String getPLucAttr(String maTKhai, String pbanTKhai, String loaiTKhai, String plucID, String attr) {
    String tkhaiNodeName = "TKhai";
    if (prefix != null) {
      tkhaiNodeName = prefix + ":" + tkhaiNodeName;
    }
    String dsPLucNodeName = "DSachPLuc";
    if (prefix != null) {
      dsPLucNodeName = prefix + ":" + dsPLucNodeName;
    }
    NodeList nList = dmucDoc.getElementsByTagName(tkhaiNodeName);
    for (int temp = 0; temp < nList.getLength(); temp++) {
      Node nNode = nList.item(temp);
      if (nNode.getNodeType() == 1) {
        Element eElement = (Element)nNode;
        if ((maTKhai.equals(eElement.getAttribute("maTKhai"))) && 
          (pbanTKhai.equals(eElement.getAttribute("pbanTKhai"))) && 
          (loaiTKhai.equals(eElement.getAttribute("loaiTKhai")))) {
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
  
  public String getTenPLuc(String maTKhai, String pbanTKhai, String loaiTKhai, String plucID) { return getTTinPLuc(maTKhai, pbanTKhai, loaiTKhai, plucID, "TenPLuc"); }
  
  public String getXSLTPLuc(String maTKhai, String pbanTKhai, String loaiTKhai, String plucID) {
    return getTTinPLuc(maTKhai, pbanTKhai, loaiTKhai, plucID, "PLucXSLT");
  }
  
  public String getExcelTemplatePLuc(String maTKhai, String pbanTKhai, String loaiTKhai, String plucID) { return getTTinPLuc(maTKhai, pbanTKhai, loaiTKhai, plucID, "PLucExcelTemplate"); }
  
  private String getTTinPLuc(String maTKhai, String pbanTKhai, String loaiTKhai, String plucID, String nodeName) {
    String tkhaiNodeName = "TKhai";
    if (prefix != null) {
      tkhaiNodeName = prefix + ":" + tkhaiNodeName;
    }
    String dsPLucNodeName = "DSachPLuc";
    if (prefix != null) {
      nodeName = prefix + ":" + nodeName;
    }
    NodeList nList = dmucDoc.getElementsByTagName(tkhaiNodeName);
    for (int temp = 0; temp < nList.getLength(); temp++) {
      Node nNode = nList.item(temp);
      if (nNode.getNodeType() == 1) {
        Element eElement = (Element)nNode;
        if ((maTKhai.equals(eElement.getAttribute("maTKhai"))) && 
          (pbanTKhai.equals(eElement.getAttribute("pbanTKhai"))) && 
          (loaiTKhai.equals(eElement.getAttribute("loaiTKhai")))) {
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
