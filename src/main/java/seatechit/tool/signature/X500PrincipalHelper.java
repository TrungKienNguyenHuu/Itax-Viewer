package seatechit.tool.signature;

import java.util.ArrayList;
import java.util.Iterator;
import javax.security.auth.x500.X500Principal;

public class X500PrincipalHelper
{
  public static int LEASTSIGNIFICANT = 0;
  public static int MOSTSIGNIFICANT = 1;
  
  public static final String attrCN = "CN";
  
  public static final String attrOU = "OU";
  public static final String attrO = "O";
  public static final String attrC = "C";
  public static final String attrL = "L";
  public static final String attrST = "ST";
  public static final String attrSTREET = "STREET";
  public static final String attrEMAIL = "EMAILADDRESS";
  public static final String attrUID = "UID";
  ArrayList rdnNameArray = new ArrayList();
  
  private static final String attrTerminator = "=";
  

  public X500PrincipalHelper() {}
  

  public X500PrincipalHelper(X500Principal principal)
  {
    parseDN(principal.getName("RFC2253"));
  }
  public void setPrincipal(X500Principal principal)
  {
    parseDN(principal.getName("RFC2253"));
  }

  public String getCN()
  {
    return findPart("CN");
  }

  public String getOU()
  {
    return findPart("OU");
  }

  public String getO()
  {
    return findPart("O");
  }
  

  public String getC()
  {
    return findPart("C");
  }

  public String getL()
  {
    return findPart("L");
  }

  public String getST()
  {
    return findPart("ST");
  }

  public String getSTREET()
  {
    return findPart("STREET");
  }

  public String getEMAILDDRESS()
  {
    return findPart("EMAILADDRESS");
  }
  
  public String getUID() {
    return findPart("UID");
  }

  private void parseDN(String dn)
    throws IllegalArgumentException
  {
    int startIndex = 0;
    char c = '\000';
    ArrayList nameValues = new ArrayList();
    

    rdnNameArray.clear();
    
    while (startIndex < dn.length()) {
        int endIndex;
        for (endIndex = startIndex; endIndex < dn.length(); endIndex++) {
            c = dn.charAt(endIndex);
            if ((c == ',') || (c == '+'))
                break;
            if (c == '\\') {
                endIndex++;
            }
        }

        if (endIndex > dn.length()) {
            throw new IllegalArgumentException("unterminated escape " + dn);
        }
        nameValues.add(dn.substring(startIndex, endIndex));

        if (c != '+') {
            rdnNameArray.add(nameValues);
            if (endIndex != dn.length()) {
                nameValues = new ArrayList();
            } else
                nameValues = null;
        }
        startIndex = endIndex + 1;
    }
    if (nameValues != null) {
      throw new IllegalArgumentException("improperly terminated DN " + dn);
    }
  }

  public ArrayList getAllValues(String attributeID)
  {
    ArrayList retList = new ArrayList();
    String searchPart = attributeID + "=";
    
    for (Iterator iter = rdnNameArray.iterator(); iter.hasNext();) {
      ArrayList nameList = (ArrayList)iter.next();
      String namePart = (String)nameList.get(0);
      
      if (namePart.startsWith(searchPart))
      {
        retList.add(namePart.toString().substring(searchPart.length()));
      }
    }
    
    return retList;
  }
  
  private String findPart(String attributeID)
  {
    return findSignificantPart(attributeID, MOSTSIGNIFICANT);
  }
  
  private String findSignificantPart(String attributeID, int significance) {
    String retNamePart = null;
    String searchPart = attributeID.toUpperCase() + "=";
    
    System.out.println("Searching for: " + searchPart);
    
    for (Iterator iter = rdnNameArray.iterator(); iter.hasNext();) {
        ArrayList nameList = (ArrayList)iter.next();
        String namePart = ((String)nameList.get(0)).toUpperCase();
        
        System.out.println("Checking against: " + namePart);
        
        if (namePart.startsWith(searchPart)) {
            // Use original case for the value
            retNamePart = ((String)nameList.get(0)).substring(searchPart.length());
            
            if (significance == MOSTSIGNIFICANT) {
                break;
            }
        }
    }
    return retNamePart;
}

}
