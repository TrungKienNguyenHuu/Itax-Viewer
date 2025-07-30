package ihtkk.tool.signature;

public class ITaxCertValidException extends Exception {
  private String message;
  
  public ITaxCertValidException(String message) { this.message = message; }
  
  public String getMessage() {
    return message;
  }
}
