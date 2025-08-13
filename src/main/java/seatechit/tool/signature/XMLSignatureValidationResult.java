package seatechit.tool.signature;

import java.security.cert.X509Certificate;

public class XMLSignatureValidationResult {
  public static int SIG_STATUS_GOOD = 0;
  public static int SIG_STATUS_WARNING = 1;
  public static int SIG_STATUS_ERROR = 2;
  private X509Certificate[] certChain;
  private String validMessage;
  private int validStatus;
  private String timeStamp;
  
  public XMLSignatureValidationResult() {}
  
  public String getTimeStamp()
  {
    String result = "";
    if ((timeStamp != null) && (!timeStamp.equals("")))
    {
      result = "(ký ngày ";
      result = result + timeStamp.substring(0, 2);
      result = result + " tháng ";
      result = result + timeStamp.substring(2, 4);
      result = result + " năm ";
      result = result + timeStamp.substring(4, 8);
      result = result + " , ";
      result = result + timeStamp.substring(8, 10);
      result = result + " giờ ";
      result = result + timeStamp.substring(10, 12);
      result = result + " phút ";
      result = result + timeStamp.substring(12);
      result = result + " giây)";
      return result;
    }
    
    return result;
  }
  
  public void setTimeStamp(String timeStamp) { this.timeStamp = timeStamp; }
  
  public int getValidStatus() {
    return validStatus;
  }
  
  public void setValidStatus(int validStatus) { this.validStatus = validStatus; }
  
  public X509Certificate[] getCertChain() {
    return certChain;
  }
  
  public void setCertChain(X509Certificate[] certChain) { this.certChain = certChain; }
  
  public String getValidMessage() {
    if (validStatus == SIG_STATUS_GOOD) {
      return "Chữ ký điện tử hợp lệ";
    }
    return validMessage;
  }
  
  public void setValidMessage(String validMessage) { this.validMessage = validMessage; }
  
  public String getSignerName() {
    String subject = "[Không biết chủ thể của chứng thư số]";
    if (certChain != null) {
        X509Certificate cert = certChain[0];
        System.out.println("Certificate Subject DN: " + cert.getSubjectX500Principal().getName());
        
        X500PrincipalHelper helper = new X500PrincipalHelper(cert.getSubjectX500Principal());
        String cn = helper.getCN();
        System.out.println("Found CN: " + cn);
        
        if (cn != null) {
            subject = cn;
        } else {
            // Fallback to Organization if CN not found
            subject = helper.getO();
        }
    } else {
        System.out.println("Certificate chain is null");
    }
    return subject;
    }
}
