package ihtkk.tool.utils;

import java.io.File;
import java.io.IOException;
import org.apache.commons.io.FileUtils;
import ihtkk.tool.ITaxViewerException;






public class TaxViewerUtils
{
  public TaxViewerUtils() {}
  
  public static String createTemFileFromTextData(String dataContentXML)
    throws ITaxViewerException, IOException
  {
    String baseFileName = "TemKDTT";
    File tempfile = File.createTempFile(baseFileName, ".tmp");
    tempfile.deleteOnExit();
    FileUtils.writeStringToFile(tempfile, dataContentXML, "UTF-8");
    
    return tempfile.getAbsolutePath();
  }
  
  public static String getDataContectXMLFromBase64(String dataContentXMLBase64Encode) throws Exception
  {
    String datacontentXML = "";
    try {
      byte[] contentXMLBase64Decode = 
        Base64Utils.base64Decode(dataContentXMLBase64Encode);
      datacontentXML = new String(contentXMLBase64Decode, "UTF-8");
    } catch (Exception ex) {
      throw new ITaxViewerException("Lỗi chuyển đổi dữ liệu: " + 
        ex.getLocalizedMessage());
    }
    return datacontentXML;
  }
}
