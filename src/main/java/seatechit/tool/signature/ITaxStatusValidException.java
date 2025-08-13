package seatechit.tool.signature;

public class ITaxStatusValidException extends Exception {
  private String message;
  
  public ITaxStatusValidException(String message) { this.message = message; }
  
  public String getMessage() {
    return message;
  }
}
