package ihtkk.tool.signature;

public class ITaxSigValidException extends Exception {
  private String message;
  
  public ITaxSigValidException(String message) { this.message = message; }
  
  public String getMessage() {
    return message;
  }
}
