package seatechit.tool.taxview;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import javax.xml.parsers.ParserConfigurationException;
import org.eclipse.swt.browser.Browser;
import org.eclipse.swt.events.SelectionEvent;
import org.eclipse.swt.events.SelectionListener;
import org.eclipse.swt.graphics.Color;
import org.eclipse.swt.graphics.Image;
import org.eclipse.swt.graphics.RGB;
import org.eclipse.swt.layout.GridData;
import org.eclipse.swt.layout.GridLayout;
import org.eclipse.swt.widgets.Composite;
import org.eclipse.swt.widgets.Control;
import org.eclipse.swt.widgets.Display;
import org.eclipse.swt.widgets.Event;
import org.eclipse.swt.widgets.FileDialog;
import org.eclipse.swt.widgets.Listener;
import org.eclipse.swt.widgets.Menu;
import org.eclipse.swt.widgets.MenuItem;
import org.eclipse.swt.widgets.Shell;
import org.eclipse.swt.widgets.ToolBar;
import org.eclipse.swt.widgets.ToolItem;
import org.xml.sax.SAXException;
import seatechit.tool.ConfigInfo;
import seatechit.tool.ITaxViewerException;
import seatechit.tool.SWidgetTool;
import seatechit.tool.TaxViewExceptionHandler;
import seatechit.tool.utils.TaxViewerUtils;

public class TaxViewer
{
  private static ConfigInfo config;
  private static final Display display = new Display();
  private static final Color bgViewColor = new Color(display, new RGB(242, 242, 242));
  private static final Shell shell = new Shell();
  private static Composite viewArea;
  private static Composite actionArea;
  private static Menu appMenu;
  private static ToolBar appToolBar;
  private HSoThueViewer hsoViewer;
  private Browser homeBrowser;
  public TaxViewer() {}
  public static void main(String[] args)
  {
    String hsoFileName = null;
    String dataContentXML = "";
    if (args.length == 1) {
      hsoFileName = args[0];
    } else if (args.length == 2) {
      dataContentXML = args[1];
      

      try
      {
        dataContentXML = TaxViewerUtils.getDataContectXMLFromBase64(dataContentXML);
        hsoFileName = TaxViewerUtils.createTemFileFromTextData(dataContentXML);
      } catch (ITaxViewerException e) {
        e.printStackTrace();
        TaxViewExceptionHandler.handleError(shell, e);
        shell.dispose();
        display.dispose();
        System.exit(0);
      } catch (UnsupportedEncodingException e) {
        TaxViewExceptionHandler.handleError(shell, e);
        shell.dispose();
        display.dispose();
        System.exit(0);
      } catch (IOException e) {
        TaxViewExceptionHandler.handleError(shell, e);
        shell.dispose();
        display.dispose();
        System.exit(0);
      } catch (Exception e) {
        TaxViewExceptionHandler.handleError(shell, e);
        shell.dispose();
        display.dispose();
        System.exit(0);
      }
    }
    try
    {
      init();
    } catch (Exception ex) {
      TaxViewExceptionHandler.handleError(shell, ex);
      shell.dispose();
      display.dispose();
      System.exit(0);
    }
    try {
      new TaxViewer().start(hsoFileName);
    } catch (Exception ex) {
      TaxViewExceptionHandler.handleError(shell, ex);
    }
  }
  
  private static void init() throws Exception { config = new ConfigInfo();
    System.setProperty("java.net.useSystemProxies", "true");
  }

  public void start(String hsoFileName)
    throws IOException, SAXException, ParserConfigurationException
  {
    shell.setBackground(bgViewColor);
    shell.setText("iTax Viewer");
    shell.setImage(new Image(shell.getDisplay(), "image\\appicon.ico"));
    shell.addListener(21, new Listener() {
      public void handleEvent(Event event) {
        TaxViewer.this.exit();
      }
    });
    createMenuToolbar();
    
    createLayout();
    
    shell.open();
    shell.setMaximized(true);
    
    if (hsoFileName == null) {
      openHomePage();
    } else {
      viewFile(hsoFileName);
    }
    
    while (!shell.isDisposed()) {
      if (!display.readAndDispatch()) {
        display.sleep();
      }
    }
  }
  
  private void createMenuToolbar() {
    appMenu = new Menu(shell, 2);
    shell.setMenuBar(appMenu);
    
    MenuItem fileMenuItem = new MenuItem(appMenu, 64);
    fileMenuItem.setText("&Tệp hồ sơ");
    
    Menu fileSubMenu = new Menu(fileMenuItem);
    fileMenuItem.setMenu(fileSubMenu);
    
    MenuItem openMenuItem = new MenuItem(fileSubMenu, 0);
    openMenuItem.setText("&Mở tệp hồ sơ");
    openMenuItem.addSelectionListener(new SelectionListener()
    {
      public void widgetSelected(SelectionEvent event)
      {
        TaxViewer.this.openFile();
      }
      public void widgetDefaultSelected(SelectionEvent event) {}
    });
    new MenuItem(fileSubMenu, 2);
    
    MenuItem printMenuItem = new MenuItem(fileSubMenu, 0);
    printMenuItem.setEnabled(false);
    printMenuItem.setText("&In hồ sơ");
    printMenuItem.addSelectionListener(new SelectionListener()
    {
      public void widgetSelected(SelectionEvent event)
      {
        try
        {
          hsoViewer.printFile();
        } catch (IOException ex) {
          TaxViewExceptionHandler.handleError(TaxViewer.shell.getShell(), ex);
        }
      }
      public void widgetDefaultSelected(SelectionEvent event) {}
    });
    new MenuItem(fileSubMenu, 2);
    
    MenuItem exitMenuItem = new MenuItem(fileSubMenu, 0);
    exitMenuItem.setText("&Thoát khỏi ứng dụng");
    exitMenuItem.addSelectionListener(new SelectionListener()
    {
      public void widgetSelected(SelectionEvent event)
      {
        TaxViewer.this.exit();
      }
      public void widgetDefaultSelected(SelectionEvent event) {}
    });

    MenuItem signatureMenu = new MenuItem(appMenu, 64);
    signatureMenu.setEnabled(false);
    signatureMenu.setText("Chữ &ký điện tử");
    
    Menu signatureSubMenu = new Menu(signatureMenu);
    signatureMenu.setMenu(signatureSubMenu);
    
    MenuItem verifyMenuItem = new MenuItem(signatureSubMenu, 0);
    verifyMenuItem.setText("&Xác minh chữ ký điện tử");
    verifyMenuItem.addSelectionListener(new SelectionListener()
    {
      public void widgetSelected(SelectionEvent event)
      {
        try
        {
          hsoViewer.displaySignatureStatus();
        } catch (Exception ex) {
          TaxViewExceptionHandler.handleError(TaxViewer.shell.getShell(), ex);
        }
      }
      public void widgetDefaultSelected(SelectionEvent event) {}
    });
    appToolBar = new ToolBar(shell, 131072);
    appToolBar.setBackground(bgViewColor);
    appToolBar.setBounds(5, 5, 129, 22);
    
    ToolItem openToolItem = new ToolItem(appToolBar, 8);
    openToolItem.setToolTipText("Mở tệp hồ sơ");
    openToolItem.setImage(new Image(shell.getDisplay(), "image\\open.ico"));
    openToolItem.addSelectionListener(new SelectionListener()
    {
      public void widgetSelected(SelectionEvent event)
      {
        TaxViewer.this.openFile();
      }
      public void widgetDefaultSelected(SelectionEvent event) {}
    });
    new ToolItem(appToolBar, 2);
    
    ToolItem printToolItem = new ToolItem(appToolBar, 0);
    printToolItem.setEnabled(false);
    printToolItem.setToolTipText("In hồ sơ");
    printToolItem.setImage(new Image(shell.getDisplay(), "image\\print.ico"));
    printToolItem.addSelectionListener(new SelectionListener()
    {
      public void widgetSelected(SelectionEvent event)
      {
        try
        {
          hsoViewer.printFile();
        } catch (IOException ex) {
          TaxViewExceptionHandler.handleError(TaxViewer.shell.getShell(), ex);
        }
      }
      public void widgetDefaultSelected(SelectionEvent event) {}
    });
    new ToolItem(appToolBar, 2);
    
    ToolItem verifyToolItem = new ToolItem(appToolBar, 0);
    verifyToolItem.setEnabled(false);
    verifyToolItem.setToolTipText("Xác minh chữ ký điện tử");
    verifyToolItem.setImage(new Image(shell.getDisplay(), "image\\verify.ico"));
    verifyToolItem.addSelectionListener(new SelectionListener()
    {
      public void widgetSelected(SelectionEvent event)
      {
        try
        {
          hsoViewer.displaySignatureStatus();
        } catch (Exception ex) {
          TaxViewExceptionHandler.handleError(TaxViewer.shell.getShell(), ex);
        }
      }
      public void widgetDefaultSelected(SelectionEvent event) {}
    });
    appToolBar.pack();
  }
  
  private void createLayout() { GridLayout gridLayout = new GridLayout();
    gridLayout.marginWidth = 0;
    gridLayout.marginHeight = 0;
    gridLayout.verticalSpacing = 0;
    gridLayout.horizontalSpacing = 0;
    shell.setLayout(gridLayout);
    GridData gridData = new GridData(4, 4, true, true);
    shell.setLayoutData(gridData);
    
    viewArea = new Composite(shell, 0);
    viewArea.setBackground(bgViewColor);
    gridLayout = new GridLayout();
    gridLayout.marginWidth = 1;
    gridLayout.marginHeight = 1;
    gridLayout.verticalSpacing = 1;
    gridLayout.horizontalSpacing = 1;
    viewArea.setLayout(gridLayout);
    gridData = new GridData(4, 4, true, true);
    viewArea.setLayoutData(gridData);
    
    actionArea = new Composite(shell, 0);
    actionArea.setBackground(bgViewColor);
    gridLayout = new GridLayout();
    gridLayout.marginWidth = 0;
    gridLayout.marginHeight = 0;
    gridLayout.verticalSpacing = 0;
    gridLayout.horizontalSpacing = 0;
    actionArea.setLayout(gridLayout);
    gridData = new GridData(4, 4, false, false);
    actionArea.setLayoutData(gridData);
  }
  
  private void openHomePage() throws IOException, SAXException, ParserConfigurationException {
    homeBrowser = new Browser(viewArea, 0);
    SWidgetTool.boderControl(homeBrowser, 18);
    homeBrowser.addListener(35, new Listener() {
      public void handleEvent(Event event) {
        event.doit = false;
      }
    });
    homeBrowser.setUrl(config.getHomePageFileName());
    viewArea.layout();
    shell.layout();
  }
  
  private void openFile() { FileDialog fd = new FileDialog(shell, 4096);
    fd.setFilterPath("C:/");
    String[] filterExt = { "*.xml", "*.*" };
    String[] filterNamne = { "Tax Files (*.xml)", "All Files (*.*)" };
    fd.setFilterExtensions(filterExt);
    fd.setFilterNames(filterNamne);
    String openedFilePath = fd.open();
    if (openedFilePath != null)
      viewFile(openedFilePath);
  }
  
  private void viewFile(String fileName) {
    try {
        // Close existing resources first
        if (homeBrowser != null) {
            homeBrowser.dispose();
            Control[] children = viewArea.getChildren();
            for (int i = 0; i < children.length; i++) {
                children[i].dispose();
            }
            homeBrowser = null;
        }
        
        // Make sure previous viewer is properly disposed
        if (hsoViewer != null) {
            try {
                hsoViewer.dispose();
                // Add small delay to ensure resources are released
                Thread.sleep(100);
            } catch (Exception e) {
                System.out.println("Warning: Error disposing previous viewer: " + e.getMessage());
            }
            hsoViewer = null;
        }

        // Force garbage collection to release file handles
        System.gc();
        
        // Create new viewer with retry mechanism
        int retryCount = 0;
        while (retryCount < 3) {
            try {
                hsoViewer = new HSoThueViewer(config, viewArea, actionArea, fileName);
                hsoViewer.createHSoViewer();
                break;
            } catch (IOException e) {
                retryCount++;
                if (retryCount >= 3) {
                    throw e;
                }
                // Wait before retry
                Thread.sleep(500);
            }
        }

        enableMenu();
        shell.layout();
    } catch (Exception ex) {
        try {
            openHomePage();
            TaxViewExceptionHandler.handleError(shell, ex);
        } catch (Exception hex) {
            TaxViewExceptionHandler.handleError(shell, hex);
        }
    }
  }
  
  public static void enableMenu() {
    for (int i = 0; i < appMenu.getItemCount(); i++) {
      MenuItem item = appMenu.getItem(i);
      item.setEnabled(true);
      Menu menu = item.getMenu();
      for (int j = 0; j < menu.getItemCount(); j++) {
        menu.getItem(j).setEnabled(true);
      }
    }
    for (int k = 0; k < appToolBar.getItemCount(); k++) {
      appToolBar.getItem(k).setEnabled(true);
    }
  }
  

  private void exit()
  {
    if (hsoViewer != null) {
      hsoViewer.dispose();
    }
    display.dispose();
    shell.dispose();
    System.exit(0);
  }
}
