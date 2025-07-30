package ihtkk.tool.taxdoc;

public class ITaxInvalidDocException extends Exception {
  private String message;
  
  public ITaxInvalidDocException(String message) { this.message = message; }
  
  public String getMessage() {
    return message;
  }
}
