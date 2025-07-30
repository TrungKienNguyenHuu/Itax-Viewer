package ihtkk.tool.taxview;

import java.awt.Desktop;
import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import javax.xml.parsers.ParserConfigurationException;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.lang3.StringEscapeUtils;
import org.eclipse.swt.browser.Browser;
import org.eclipse.swt.browser.BrowserFunction;
import org.eclipse.swt.browser.LocationAdapter;
import org.eclipse.swt.browser.LocationEvent;
import org.eclipse.swt.browser.ProgressAdapter;
import org.eclipse.swt.browser.ProgressEvent;
import org.eclipse.swt.browser.ProgressListener;
import org.eclipse.swt.events.KeyEvent;
import org.eclipse.swt.events.KeyListener;
import org.eclipse.swt.events.MouseEvent;
import org.eclipse.swt.events.MouseListener;
import org.eclipse.swt.layout.RowLayout;
import org.eclipse.swt.ole.win32.OleAutomation;
import org.eclipse.swt.ole.win32.OleClientSite;
import org.eclipse.swt.ole.win32.OleFrame;
import org.eclipse.swt.ole.win32.Variant;
import org.eclipse.swt.widgets.Composite;
import org.eclipse.swt.widgets.Control;
import org.eclipse.swt.widgets.Event;
import org.eclipse.swt.widgets.Link;
import org.eclipse.swt.widgets.Listener;
import org.eclipse.swt.widgets.Menu;
import org.eclipse.swt.widgets.Shell;
import ihtkk.tool.ConfigInfo;
import ihtkk.tool.ITaxViewerException;
import ihtkk.tool.SWidgetTool;
import ihtkk.tool.TaxViewExceptionHandler;
import ihtkk.tool.signature.XMLSignatureValidationResult;
import ihtkk.tool.taxdoc.HSoThue;
import ihtkk.tool.taxdoc.HSoThueFactory;
import ihtkk.tool.taxdoc.ITaxInvalidDocException;
import ihtkk.tool.taxdoc.PLuc;

public class HSoThueViewer
{
  public static final int COLOR_BORDER = 18;
  private HSoThue hso;
  private static Browser fileBrowser = null;
  private static OleFrame oleExcelFrame;
  private static OleAutomation oleExcel;
  private static OleClientSite oleExcelClientSite;
  private static Composite viewArea;
  private static String displaySigFunctionName = "displaySigFunction";
  private static Composite actionArea;
  private Control selectedControl;
  
  public HSoThueViewer(ConfigInfo config, Composite viewArea, Composite actionArea, String tkhaiFileName) throws IOException, ParserConfigurationException, ITaxInvalidDocException, ITaxViewerException { viewArea = viewArea;
    actionArea = actionArea;
    hso = HSoThueFactory.createHSoThue(tkhaiFileName, config);
  }
  
  public void createHSoViewer() throws IOException { if ("1".equals(hso.getViewMethod())) {
      closeHTMLViewer();
      createHTMLViewer();
    } else if (!"2".equals(hso.getViewMethod()))
    {
      "3".equals(hso.getViewMethod());
    }
    
    if (hso.getPlucList() != null)
      createPLucViewLink();
  }
  
  private void createPLucViewLink() {
    Collection plucList = hso.getPlucList();
    Composite composite = new Composite(actionArea, 0);
    composite.setBackground(actionArea.getBackground());
    RowLayout rowLayout = new RowLayout();
    rowLayout.marginLeft = 5;
    rowLayout.marginTop = 5;
    rowLayout.marginRight = 5;
    rowLayout.marginBottom = 5;
    rowLayout.spacing = 5;
    composite.setLayout(rowLayout);
    
    final Link tkhaiLk = SWidgetTool.createFlatLink(composite, 3, 2, 1, 18, "Tờ khai");
    tkhaiLk.setToolTipText(hso.getTenHSo());
    tkhaiLk.addMouseListener(new MouseListener() {
      public void mouseDown(MouseEvent e) {
        viewHSoHTML();
        HSoThueViewer.this.enableLink(tkhaiLk);
      }
      


      public void mouseUp(MouseEvent e) {}
      


      public void mouseDoubleClick(MouseEvent e) {}
    });
    Iterator it = plucList.iterator();
    while (it.hasNext()) {
      final PLuc pluc = (PLuc)it.next();
      final Link plucLk = SWidgetTool.createFlatLink(composite, 3, 2, 1, 18, pluc.getPlucID());
      plucLk.setToolTipText(pluc.getPlucName());
      plucLk.addMouseListener(new MouseListener() {
        public void mouseDown(MouseEvent e) {
          try {
            HSoThueViewer.this.viewPLucHTML(pluc);
            HSoThueViewer.this.enableLink(plucLk);
          } catch (IOException ioEx) {
            TaxViewExceptionHandler.handleError(HSoThueViewer.actionArea.getShell(), ioEx);
          }
        }
        

        public void mouseUp(MouseEvent e) {}
        

        public void mouseDoubleClick(MouseEvent e) {}
      });
    }
    
    actionArea.layout();
  }
  
  private void enableLink(Link selectedLk) { selectedLk.setEnabled(false);
    if (selectedControl != null) {
      selectedControl.setEnabled(true);
    }
    selectedControl = selectedLk;
  }
  
  public void viewHSoHTML() { viewHTML(hso.getTkhaiHTML(), hso.getOrientation()); }
  
  private void viewPLucHTML(PLuc pluc) throws IOException
  {
    viewHTML(pluc.getPlucHTML(), pluc.getOrientation());
  }
  
  private void viewHTML(String html, String pageFormat) {
    if (pageFormat.equals("1")) {
      fileBrowser.execute("document.getElementById('tkhaiTable').width='1262px';");
    } else if (pageFormat.equals("0")) {
      fileBrowser.execute("document.getElementById('tkhaiTable').width='892px';");
    }
    fileBrowser.execute("document.getElementById('tkhai').innerHTML=\"" + StringEscapeUtils.escapeJava(html) + "\";");
    fileBrowser.setFocus();
  }
  
  public void displaySignatureStatus() throws Exception { Collection validationResult = hso.getSigValidationResult();
    if (validationResult.isEmpty()) {
      throw new Exception("Hồ sơ không có chữ ký điện tử");
    }
    new SignatureList(viewArea.getShell(), 67680, validationResult).open();
  }
  
  public void dispose() {
    Control[] children = viewArea.getChildren();
    for (int i = 0; i < children.length; i++) {
      children[i].dispose();
    }
    children = actionArea.getChildren();
    for (int i = 0; i < children.length; i++) {
      children[i].dispose();
    }
    closeHTMLViewer();
    closeExcelViewer();
  }
  
  public void createHTMLViewer() throws IOException { if (fileBrowser != null) {
      fileBrowser.dispose();
    }
    fileBrowser = new Browser(viewArea, 0);
    SWidgetTool.boderControl(fileBrowser, 18);
    fileBrowser.addListener(35, new Listener() {
      public void handleEvent(Event event) {
        event.doit = false;
      }
    });
    String runhtml = new File("data\\run.html").toURI().toURL().toString();
    fileBrowser.setUrl(runhtml);

    fileBrowser.addProgressListener(new ProgressListener()
    {
      public void completed(ProgressEvent event)
      {
        try
        {
          HSoThueViewer.fileBrowser.execute("showLoadingMsgBox('Đang đọc tệp hồ sơ...');");
          String xmlFileName = new File(hso.getHsoViewFileName()).toURI().toURL().toString();
          String xsltFileName = new File(hso.getXsltFile()).toURI().toURL().toString();
          
          String html = (String)HSoThueViewer.fileBrowser.evaluate(
            "return transform('" + xmlFileName + "','" + xsltFileName + "');");
          HSoThueViewer.fileBrowser.execute("document.getElementById('tkhai').innerHTML=\"" + StringEscapeUtils.escapeJava(html) + "\";");
          hso.setTkhaiHTML(html);
          
          Double htmlWidth = (Double)HSoThueViewer.fileBrowser.evaluate("return document.getElementById('tkhaiTable').offsetWidth");
          hso.setPageWidth(htmlWidth);
          if (hso.getPlucList() != null) {
            for (Object obj : hso.getPlucList()) {
              PLuc pluc = (PLuc)obj;
              xsltFileName = new File(pluc.getPlucXSLTFile()).toURI().toURL().toString();
              html = (String)HSoThueViewer.fileBrowser.evaluate(
                "return transform('" + xmlFileName + "','" + xsltFileName + "');");
              HSoThueViewer.fileBrowser.execute("document.getElementById('tkhai').innerHTML=\"" + StringEscapeUtils.escapeJava(html) + "\";");
              htmlWidth = (Double)HSoThueViewer.fileBrowser.evaluate("return document.getElementById('tkhaiTable').offsetWidth");
              pluc.setPlucHTML(html);
              pluc.setPageWidth(htmlWidth);
            }
          }
          viewHSoHTML();
          HSoThueViewer.fileBrowser.execute("document.getElementById('signature').innerHTML=\"" + StringEscapeUtils.escapeJava(HSoThueViewer.this.getSigStatusHTML(hso)) + "\";");
          HSoThueViewer.fileBrowser.execute("hideMsgBox();");
        } catch (Exception ex) {
          TaxViewExceptionHandler.handleError(HSoThueViewer.viewArea.getShell(), ex);
        }
      }
      



      public void changed(ProgressEvent event) {}
    });
    fileBrowser.addKeyListener(new KeyListener()
    {
      public void keyReleased(KeyEvent e)
      {
        if (((e.stateMask & 0x40000) == 262144) && 
          (e.keyCode == 112)) {
          try {
            printFile();
          } catch (IOException ex) {
            TaxViewExceptionHandler.handleError(HSoThueViewer.viewArea.getShell(), ex);
          }
        }
      }
      




      public void keyPressed(KeyEvent e)
      {
        if (((e.stateMask & 0x40000) == 262144) && 
          (e.keyCode == 112)) {
          try {
            printFile();
          } catch (IOException ex) {
            TaxViewExceptionHandler.handleError(HSoThueViewer.viewArea.getShell(), ex);
          }
          
        }
      }
    });
    final BrowserFunction displaySigFunction = new SignatureListFunction(displaySigFunctionName);
    fileBrowser.addProgressListener(new ProgressAdapter() {
      public void completed(ProgressEvent event) {
        HSoThueViewer.fileBrowser.addLocationListener(new LocationAdapter() {
          public void changed(LocationEvent event) {
            HSoThueViewer.fileBrowser.removeLocationListener(this);
            displaySigFunction.dispose();
          }
        });
      }
    });
    viewArea.layout();
  }
  
  private String getSigStatusHTML(HSoThue hso) throws IOException { Collection validationResults = hso.getSigValidationResult();
    Iterator ito = validationResults.iterator();
    


    String sigStatusMsgColor = "green";
    String subject = null;
    String msgHTML = "<hr width=\"100%\" style=\"color: #C0C0C0; height: 1px\"><table onclick=\"displaySig();\" border=\"0\" cellpadding=\"0\" cellspacing=\"5\" style=\"cursor:hand;\">";
    
    while (ito.hasNext()) {
      String sigStatusMsg = "Ký điện tử bởi: ";
      XMLSignatureValidationResult valResult = (XMLSignatureValidationResult)ito.next();
      subject = "<em>" + valResult.getSignerName() + "</em>";
      sigStatusMsg = sigStatusMsg + subject;
      String sigImageURL; if (XMLSignatureValidationResult.SIG_STATUS_GOOD == valResult
        .getValidStatus()) {
        sigStatusMsg = sigStatusMsg + valResult.getTimeStamp();
        sigImageURL = new File("image\\valid_sig.png").toURI()
          .toURL().toString();

      }
      else if (XMLSignatureValidationResult.SIG_STATUS_ERROR == valResult.getValidStatus()) {
        sigStatusMsgColor = "red";
        sigImageURL = new File("image\\error_sig.png").toURI()
          .toURL().toString();
        sigStatusMsg = sigStatusMsg + ". " + 
          valResult.getValidMessage();
      } else {
        sigImageURL = 
          new File("image\\warning_sig.png").toURI().toURL().toString();
        sigStatusMsg = sigStatusMsg + ". " + 
          valResult.getValidMessage();
      }
      msgHTML = 
      





        msgHTML + "<tr>" + " <td style=\"vertical-align:middle\"><img src=\"" + sigImageURL + "\"/></td>" + " <td style=\"vertical-align:middle;font-family:arial;color:" + sigStatusMsgColor + "\">" + sigStatusMsg + ".</td>" + "</tr>";
    }
    msgHTML = msgHTML + "</table>";
    return msgHTML;
  }
  


  public void createExcelViewer(String templatefileName, String dataFileName)
    throws IOException
  {
    String strXML = null;
    
    closeHTMLViewer();
    
    strXML = readFile(dataFileName, StandardCharsets.UTF_8);
    
    oleExcelFrame = new OleFrame(viewArea, 0);
    SWidgetTool.boderControl(oleExcelFrame, 18);
    oleExcelClientSite = new OleClientSite(oleExcelFrame, 0, 
      new File(templatefileName));
    oleExcelFrame.setFileMenus(viewArea.getShell().getMenuBar().getItems());
    oleExcelClientSite.doVerb(-5);
    oleExcelClientSite.exec(24, 
      0, null, null);
    viewArea.layout();
    
    oleExcel = new OleAutomation(oleExcelClientSite);
    
    int[] rgdispid = oleExcel.getIDsOfNames(new String[] { "Application" });
    int dispIdMember = rgdispid[0];
    Variant result = oleExcel.getProperty(dispIdMember);
    
    OleAutomation oleExcelApp = result.getAutomation();
    rgdispid = oleExcelApp.getIDsOfNames(new String[] { "Workbooks" });
    dispIdMember = rgdispid[0];
    result = oleExcelApp.getProperty(dispIdMember);
    
    OleAutomation oleExcelWorkbooks = result.getAutomation();
    rgdispid = oleExcelWorkbooks.getIDsOfNames(new String[] { "Item" });
    dispIdMember = rgdispid[0];
    result = oleExcelWorkbooks.getProperty(dispIdMember, 
      new Variant[] { new Variant(1) });
    
    OleAutomation oleExcelWorkbook = result.getAutomation();
    rgdispid = oleExcelWorkbook.getIDsOfNames(new String[] { "XmlMaps" });
    dispIdMember = rgdispid[0];
    result = oleExcelWorkbook.getProperty(dispIdMember, 
      new Variant[] { new Variant(1) });
    
    OleAutomation oleExcelXmlMap = result.getAutomation();
    rgdispid = oleExcelXmlMap.getIDsOfNames(new String[] { "ImportXml" });
    dispIdMember = rgdispid[0];
    result = oleExcelXmlMap.invoke(dispIdMember, 
      new Variant[] { new Variant(strXML) });
  }
  
  public void printFile() throws IOException {
    String baseFileName = FilenameUtils.getBaseName(hso.getHsoFileName());
    File tempfile = File.createTempFile(baseFileName, ".pdf");
    tempfile.deleteOnExit();
    String tkhaiPDFURL = "";
    ArrayList<File> printFiles = new ArrayList();
    String width = "";
    String widthLandscape = "";
    width = Integer.valueOf(hso.getPageWidth().intValue()).toString();
    boolean orientation = hso.getOrientation().equalsIgnoreCase("1");
    boolean objPDFRunable = false;
    String script = "return getPdfVer()";
    Double pdfVer = (Double)fileBrowser.evaluate(script);
    
    if ((pdfVer != null) && (!"".equals(pdfVer)))
    {

      if (pdfVer.doubleValue() >= 9.0D)
      {
        objPDFRunable = true;
      }
      else {
        objPDFRunable = false;
      }
      

    }
    else {
      objPDFRunable = false;
    }
    
    if (orientation)
    {
      if (hso.getPageWidth().doubleValue() < 1262.0D)
      {
        width = "1262px";
      }
      

    }
    else if (hso.getPageWidth().doubleValue() < 892.0D)
    {
      width = "892px";
    }
    
    String beginBlock = 
      "<div style='background-color:white; padding:0px 0px 0px 0px' border='0' align='center'> \n<table cellpadding='0' cellspacing='0' border='0' width = '" + 
      width + "'  align='center'>\n" + 
      "<tr> \n" + 
      "<td align='left' id='tkhai'> \n";
    String endBlock = "</td>\n</tr> \n</table> \n </div> \n";
    





    String sig = getSigStatusHTML(hso);
    URL stylesheet = null;
    if (hso.getXsltFile().contains("CTu"))
    {
      stylesheet = new File("data\\css\\ihtkk_ntdt.css").toURI().toURL();
    }
    else
    {
      stylesheet = new File("data\\css\\ihtkk.css").toURI().toURL();
    }
    
    String html = "";
    

    html = beginBlock + hso.getTkhaiHTML() + endBlock;
    html = html.replaceAll("<div id=\"sigDiv\"></div>", sig);
    html = html.replaceAll("<DIV id=sigDiv></DIV>", sig);
    File hsofile = File.createTempFile("hso" + baseFileName, ".pdf");
    hsofile.deleteOnExit();
    if (objPDFRunable)
    {
      new TKhaiConverter().convertToHSoPDF(html, stylesheet, orientation, hsofile, false, hso.getPageWidth());
    }
    else
    {
      new TKhaiConverter().convertToHSoPDF(html, stylesheet, orientation, hsofile, true, hso.getPageWidth());
    }
    
    printFiles.add(hsofile);
    
    if (hso.getPlucList() != null) {
      for (Object obj : hso.getPlucList()) {
        PLuc pluc = (PLuc)obj;
        html = "";
        width = Integer.valueOf(pluc.getPageWidth().intValue()).toString();
        orientation = pluc.getOrientation().equalsIgnoreCase("1");
        if (orientation)
        {
          if (pluc.getPageWidth().doubleValue() < 1262.0D)
          {
            width = "1262px";
          }
          

        }
        else if (pluc.getPageWidth().doubleValue() < 892.0D)
        {
          width = "892px";
        }
        
        beginBlock = 
        


          "<div style='background-color:white; padding:0px 0px 0px 0px' border='0' align='center'> \n<table cellpadding='0' cellspacing='0' border='0' width = '" + width + "'  align='center'>\n" + "<tr> \n" + "<td align='left' id='tkhai'> \n";
        endBlock = "</td>\n</tr> \n</table> \n </div> \n";
        


        html = beginBlock + pluc.getPlucHTML() + endBlock;
        html = html.replaceAll("<div id=\"sigDiv\"></div>", sig);
        html = html.replaceAll("<DIV id=sigDiv></DIV>", sig);
        File plucfile = File.createTempFile("hso" + baseFileName, ".pdf");
        plucfile.deleteOnExit();
        new TKhaiConverter().convertToHSoPDF(html, stylesheet, orientation, plucfile, false, pluc.getPageWidth());
        
        printFiles.add(plucfile);
      }
    }
    

    tkhaiPDFURL = tempfile.toURI().toURL().toString();
    try {
      new TKhaiConverter().mergePDF(printFiles, tempfile);
    }
    catch (Exception ex)
    {
      ex.printStackTrace();
    }
    if (objPDFRunable)
    {
      script = 
        "var objPDF= '<object id=\"tkhaiPDF\" width=\"0\" height=\"0\" onreadystatechange=\"this.printWithDialog();\" type=\"application/pdf\" data=\"" + tkhaiPDFURL + "\"></object>';\n" + "document.body.insertAdjacentHTML('beforeEnd', objPDF);\n";
      fileBrowser.execute(script);





    }
    else
    {




      Desktop desktop = Desktop.getDesktop();
      desktop.open(tempfile);
    }
  }
  
  public void webBrowserExe(int OLECMDID)
  {
    String script = "var objBrowser= '<object id=\"browser\" width=\"0\" height=\"0\" classid=\"CLSID:8856F961-340A-11D0-A96B-00C04FD705A2\"></object>';\ndocument.body.insertAdjacentHTML('beforeEnd', objBrowser);\nbrowser.ExecWB(" + 
    

      OLECMDID + 
      ", 2);\n" + 
      "browser.outerHTML = \"\";";
    fileBrowser.execute(script);
  }
  
  public void closeHTMLViewer() {
    if (fileBrowser != null) {
      fileBrowser.dispose();
      fileBrowser = null;
    }
  }
  
  public void closeExcelViewer() {
    if (oleExcel != null) {
      oleExcel.dispose();
      oleExcel = null;
      try {
        Runtime.getRuntime().exec("taskkill /F /IM EXCEL.EXE");
      } catch (IOException ex) {
        TaxViewExceptionHandler.handleError(viewArea.getShell(), ex);
      }
      
      if (oleExcelClientSite != null) {
        oleExcelClientSite.doVerb(-6);
        oleExcelClientSite.dispose();
        oleExcelClientSite = null;
      }
      if (oleExcelFrame != null) {
        oleExcelFrame.dispose();
        oleExcelFrame = null;
      }
    }
  }
  
  private String readFile(String path, Charset encoding) throws IOException {
    byte[] encoded = Files.readAllBytes(Paths.get(path, new String[0]));
    return encoding.decode(ByteBuffer.wrap(encoded)).toString();
  }
  
  class SignatureListFunction extends BrowserFunction {
    SignatureListFunction(String name) {
      super(fileBrowser, name);
    }
    
    public Object function(Object[] arguments) {
      try {
        displaySignatureStatus();
      } catch (Exception ex) {
        TaxViewExceptionHandler.handleError(HSoThueViewer.fileBrowser.getShell(), ex);
        return Boolean.FALSE;
      }
      return Boolean.TRUE;
    }
  }
}
