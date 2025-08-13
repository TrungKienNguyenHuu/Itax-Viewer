package seatechit.tool.taxdoc;

public class PLuc {
  private String plucID;
  private String plucName;
  private String plucViewMethod;
  private String plucXSLTFile;
  private String plucExcelFile;
  private String plucHTML;
  private String orientation;
  private Double pageWidth;
  
  public PLuc() {}
  
  public Double getPageWidth() { return pageWidth; }
  
  public void setPageWidth(Double pageWidth)
  {
    this.pageWidth = pageWidth;
  }
  
  public String getOrientation() {
    return orientation;
  }
  
  public void setOrientation(String orientation) {
    this.orientation = orientation;
  }
  
  public void setPlucID(String plucID) {
    this.plucID = plucID;
  }
  
  public String getPlucID() {
    return plucID;
  }
  
  public void setPlucName(String plucName) {
    this.plucName = plucName;
  }
  
  public String getPlucName() {
    return plucName;
  }
  
  public void setPlucViewMethod(String plucViewMethod) {
    this.plucViewMethod = plucViewMethod;
  }
  
  public String getPlucViewMethod() {
    return plucViewMethod;
  }
  
  public void setPlucXSLTFile(String plucXSLTFile) {
    this.plucXSLTFile = plucXSLTFile;
  }
  
  public String getPlucXSLTFile() {
    return plucXSLTFile;
  }
  
  public void setPlucExcelFile(String plucExcelFile) {
    this.plucExcelFile = plucExcelFile;
  }
  
  public String getPlucExcelFile() {
    return plucExcelFile;
  }
  
  public String getPlucHTML() { return plucHTML; }
  
  public void setPlucHTML(String plucHTML)
  {
    this.plucHTML = plucHTML;
  }
}
