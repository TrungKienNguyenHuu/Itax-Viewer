package ihtkk.tool.taxview;

import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.Insets;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.StringReader;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import org.apache.pdfbox.multipdf.PDFMergerUtility;
import org.apache.pdfbox.io.MemoryUsageSetting;
import org.zefer.pd4ml.PD4Constants;
import org.zefer.pd4ml.PD4ML;
import org.zefer.pd4ml.PD4PageMark;

public class TKhaiConverter
{
  private Dimension format = PD4ML.A4;
  private int topValue = 20;
  private int leftValue = 20;
  private int rightValue = 20;
  private int bottomValue = 10;
  private String unitsValue = "mm";
  private int userHeight = 1262;
  private int userWidth = 892;
  Dimension landscapeA4 = PD4Constants.A4;
  
  public TKhaiConverter() {}
  
  public void convertToHSoPDF(String htmlHSo, URL stylesheet, boolean landscapeValue, File output, boolean desktopOpen, Double realWidth) throws IOException { StringReader htmlHSoReder = new StringReader("<html><head><meta http-equiv=Content-Type content=\"text/html; charset=utf-8\"></head><body style=\"margin:0; align:center\">" + htmlHSo + "</body></html>");
    
    FileOutputStream fos = new FileOutputStream(output);
    PD4ML pd4ml = new PD4ML();
    pd4ml.addStyle(stylesheet, true);
    pd4ml.setPageSize(landscapeValue ? pd4ml.changePageOrientation(format) : format);
    pd4ml.setPageInsets(new Insets(topValue, leftValue, bottomValue, rightValue));
    pd4ml.setHtmlWidth(landscapeValue ? userHeight : userWidth);
    if (landscapeValue)
    {
      if (realWidth.doubleValue() > userHeight) {
        pd4ml.setHtmlWidth(realWidth.intValue() + 20 + 20);
      }
      
    }
    else if (realWidth.doubleValue() > userWidth) {
      pd4ml.setHtmlWidth(realWidth.intValue() + 20 + 20);
    }
    pd4ml.useTTF("java:fonts", true);
    pd4ml.setDefaultTTFs("Times New Roman", "Arial", "Courier New");
    pd4ml.generatePdfForms(true, "Times New Roman");
    pd4ml.enableTableBreaks(false);
    pd4ml.enableImgSplit(false);
    PD4PageMark footer = new PD4PageMark();
    footer.setPageNumberTemplate("$[page]/$[total]");
    footer.setTitleAlignment(0);
    footer.setPageNumberAlignment(1);
    footer.setColor(Color.BLACK);
    footer.setInitialPageNumber(1);
    footer.setPagesToSkip(0);
    footer.setFont(new Font("Times New Roman", 0, 12));
    footer.setAreaHeight(20);
    pd4ml.setPageFooter(footer);
    Map m = new HashMap();
    m.put("pd4ml.print.dialog.popup", "true");
    if (desktopOpen)
    {
      pd4ml.setDynamicParams(m);
    }
    
    pd4ml.render(htmlHSoReder, fos);
    fos.close();
  }
  
  private static final String HTML_HEADER = "<html><head><meta http-equiv=Content-Type content=\"text/html; charset=utf-8\"></head><body style=\"margin:0; align:center\">";
  private static final String HTML_FOOTER = "</body></html>";
  public void mergePDF(ArrayList<File> mergeFile, File destinationFile) throws Exception
  {
    try {
      PDFMergerUtility mergeUtility = new PDFMergerUtility();
      FileOutputStream fos = new FileOutputStream(destinationFile);
      mergeUtility.setDestinationStream(fos);
      for (File file : mergeFile) {
        mergeUtility.addSource(file);
      }
      mergeUtility.mergeDocuments(null);
      fos.close();
    }
    catch (Exception ex)
    {
      throw ex;
    }
  }
}
