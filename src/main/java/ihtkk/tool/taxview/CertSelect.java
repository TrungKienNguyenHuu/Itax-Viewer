package ihtkk.tool.taxview;

import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Set;
import org.eclipse.swt.events.SelectionAdapter;
import org.eclipse.swt.events.SelectionEvent;
import org.eclipse.swt.graphics.Image;
import org.eclipse.swt.graphics.Rectangle;
import org.eclipse.swt.widgets.Button;
import org.eclipse.swt.widgets.Dialog;
import org.eclipse.swt.widgets.Display;
import org.eclipse.swt.widgets.Label;
import org.eclipse.swt.widgets.Monitor;
import org.eclipse.swt.widgets.Shell;
import org.eclipse.swt.widgets.Table;
import org.eclipse.swt.widgets.TableColumn;
import org.eclipse.swt.widgets.TableItem;
import ihtkk.tool.signature.X500PrincipalHelper;

public class CertSelect
  extends Dialog
{
  protected String selectedCertAlias;
  protected static Shell certListShell;
  private HashMap certs;
  
  public CertSelect(Shell parent, int style, HashMap certs)
  {
    super(parent, style);
    this.certs = certs;
  }

  public String open()
  {
    createContents();
    Display display = getParent().getDisplay();
    Monitor primary = display.getPrimaryMonitor();
    Rectangle bounds = primary.getBounds();
    Rectangle rect = certListShell.getBounds();
    int x = bounds.x + (bounds.width - rect.width) / 2;
    int y = bounds.y + (bounds.height - rect.height) / 2;
    certListShell.setLocation(x, y);
    certListShell.open();
    certListShell.layout();
    while (!certListShell.isDisposed()) {
      if (!display.readAndDispatch()) {
        display.sleep();
      }
    }
    return selectedCertAlias;
  }
  


  private void createContents()
  {
    Set aliasSet = certs.keySet();
    Iterator ito = aliasSet.iterator();
    


    Calendar expireCal = Calendar.getInstance();
    
    certListShell = new Shell(getParent(), getStyle());
    certListShell.setImage(new Image(certListShell.getDisplay(), "image\\sign.gif"));
    certListShell.setSize(458, 246);
    certListShell.setText("Danh sách chứng thư số");
    
    Label lblNewLabel = new Label(certListShell, 0);
    lblNewLabel.setBounds(5, 9, 201, 13);
    lblNewLabel.setText("Chọn chứng thư số dùng để ký hồ sơ");
    
    final Table certTable = new Table(certListShell, 67584);
    certTable.setBounds(4, 28, 444, 145);
    certTable.setHeaderVisible(true);
    certTable.setLinesVisible(true);
    
    TableColumn aliasCol = new TableColumn(certTable, 0);
    aliasCol.setWidth(0);
    
    TableColumn subjectCol = new TableColumn(certTable, 0);
    subjectCol.setWidth(280);
    subjectCol.setText("Chủ thể");
    
    TableColumn issuerCol = new TableColumn(certTable, 0);
    issuerCol.setWidth(80);
    issuerCol.setText("Nhà cung cấp");
    
    TableColumn expireCol = new TableColumn(certTable, 0);
    expireCol.setWidth(80);
    expireCol.setText("Ngày hết hạn");
    
    while (ito.hasNext()) {
      String alias = (String)ito.next();
      X509Certificate cert = (X509Certificate)certs.get(alias);
      TableItem tableItem = new TableItem(certTable, 0);
      tableItem.setText(0, alias);
      tableItem.setText(1, new X500PrincipalHelper(cert.getSubjectX500Principal()).getCN());
      tableItem.setText(2, new X500PrincipalHelper(cert.getIssuerX500Principal()).getCN());
      expireCal.setTime(cert.getNotAfter());
      tableItem.setText(3, 
        expireCal.get(5) + "/" + (expireCal.get(2) + 1) + "/" + expireCal.get(1));
    }
    certTable.setSelection(0);
    
    Button selectCertButton = new Button(certListShell, 0);
    selectCertButton.addSelectionListener(new SelectionAdapter()
    {
      public void widgetSelected(SelectionEvent e) {
        selectedCertAlias = certTable.getItem(certTable.getSelectionIndex()).getText(0);
        CertSelect.certListShell.dispose();
      }
    });
    selectCertButton.setBounds(153, 186, 68, 23);
    selectCertButton.setText("&Chấp nhận");
    
    Button cancelCertButton = new Button(certListShell, 0);
    cancelCertButton.addSelectionListener(new SelectionAdapter()
    {
      public void widgetSelected(SelectionEvent e) {
        selectedCertAlias = null;
        CertSelect.certListShell.dispose();
      }
    });
    cancelCertButton.setBounds(227, 186, 68, 23);
    cancelCertButton.setText("&Bỏ qua");
  }
}
