package seatechit.tool;

import org.eclipse.swt.widgets.MessageBox;

public class TaxViewExceptionHandler {
  public TaxViewExceptionHandler() {}
  
  public static void showMsg(org.eclipse.swt.widgets.Shell shell, String msg, int iconType) {
    MessageBox messageBox = new MessageBox(shell, iconType | 0x20);
    messageBox.setText("Thông báo");
    messageBox.setMessage(msg);
    messageBox.open();
  }
  
  public static void handleError(org.eclipse.swt.widgets.Shell shell, Exception ex) { ex.printStackTrace();
    showMsg(shell, ex.getMessage(), 8);
  }
}
