package seatechit.tool;

public class ITaxViewerException extends Exception {
  private String message;
  
  public ITaxViewerException(String message) { this.message = message; }
  
  public String getMessage() {
    return message;
  }
}
