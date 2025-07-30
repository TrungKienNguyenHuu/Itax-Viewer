package ihtkk.tool.taxdoc;

import java.io.IOException;
import java.util.Collection;
import javax.xml.parsers.ParserConfigurationException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import ihtkk.tool.ConfigInfo;
import ihtkk.tool.ITaxViewerException;

public abstract class HSoThue
{
  public static final String LANDSCAPE_PAGE_FORMAT = "1";
  public static final String PORTRAIT_PAGE_FORMAT = "0";
  protected ConfigInfo config;
  protected String hsoFileName;
  protected String hsoViewFileName;
  protected Document tkhaiDoc;
  protected String maHSo;
  protected String loaiHSo;
  protected String pbanHSoXML;
  protected String tenHSo;
  protected String viewMethod;
  protected String xsdFile;
  protected String xsltFile;
  protected String excelFile;
  protected Collection plucList;
  protected Collection sigValidationResult;
  protected String tkhaiHTML;
  protected Double pageWidth;
  protected String orientation = "0";
  

  protected String prefix;
  

  public Double getPageWidth()
  {
    return pageWidth;
  }
  
  public void setPageWidth(Double pageWidth) {
    this.pageWidth = pageWidth;
  }
  
  public HSoThue(Document tkhaiDoc, String hsoFileName, ConfigInfo config) throws IOException, ParserConfigurationException, ITaxViewerException {
    this.config = config;
    this.hsoFileName = hsoFileName;
    this.tkhaiDoc = tkhaiDoc;
    
    Element rootElm = tkhaiDoc.getDocumentElement();
    prefix = rootElm.getPrefix();
  }
  
  public String getHsoViewFileName() {
    return hsoViewFileName;
  }
  
  public String getOrientation() {
    return orientation;
  }
  
  public String getViewMethod() {
    return viewMethod;
  }
  
  public String getXsdFile() {
    return xsdFile;
  }
  
  public String getXsltFile() {
    return xsltFile;
  }
  
  public String getExcelFile() {
    return excelFile;
  }
  
  public Collection getPlucList() {
    return plucList;
  }
  
  public Collection getSigValidationResult() {
    return sigValidationResult;
  }
  
  public String getMaHSo() { return maHSo; }
  
  public String getLoaiHSo()
  {
    return loaiHSo;
  }
  
  public String getPbanHSoXML() {
    return pbanHSoXML;
  }
  
  public String getTenHSo() {
    return tenHSo;
  }
  
  public String getTkhaiHTML() { return tkhaiHTML; }
  
  public void setTkhaiHTML(String tkhaiHTML)
  {
    this.tkhaiHTML = tkhaiHTML;
  }
  
  public String getHsoFileName() { return hsoFileName; }
}
