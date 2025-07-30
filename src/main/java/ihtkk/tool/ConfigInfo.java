package ihtkk.tool;

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import javax.xml.parsers.ParserConfigurationException;
import org.xml.sax.SAXException;
import ihtkk.tool.hquanform.DMucHquan;
import ihtkk.tool.hquanform1.DMucHquan1;
import ihtkk.tool.signature.CertVerifier;
import ihtkk.tool.taxCatalog.DMucDMuc;
import ihtkk.tool.taxMessage.DMucTBao;
import ihtkk.tool.taxMessageNtdt.DMucTBaoNtdt;
import ihtkk.tool.taxRegistration.DMucDKy;
import ihtkk.tool.taxmessagekdtt.DMucBKeKDTT;
import ihtkk.tool.taxmessagekdtt.DMucTBaoKDTT;
import ihtkk.tool.taxreturn.DMucTKhai;
import ihtkk.tool.taxvoucher.DMucCTu;



public class ConfigInfo
{
  private String homePageFileName;
  private DMucTKhai dmTKhai;
  private DMucCTu dmCTu;
  private DMucTBao dmTBao;
  private DMucTBaoNtdt dmTBaoNtdt;
  private DMucDMuc dmDMuc;
  private DMucDKy dmDKy;
  private String TBaoXpath;
  private String DmucXpath;
  private String DkyXpath;
  private String TBaoNtdtXpath;
  private DMucHquan dmHquan;
  private DMucHquan1 dmHquan1;
  private DMucTBaoKDTT dmTBaoKDTT;
  private DMucBKeKDTT dmBKeKDTT;
  private X509Certificate[] rootCerts;
  private X509Certificate[] trustedCerts;
  
  public ConfigInfo()
    throws IOException, SAXException, ParserConfigurationException, GeneralSecurityException
  {
    dmTKhai = new DMucTKhai("data\\DMucTKhai.xml");
    dmCTu = new DMucCTu("data\\DMucCTu.xml");
    dmTBao = new DMucTBao("data\\DMucTBao.xml");
    dmTBaoNtdt = new DMucTBaoNtdt("data\\DMucTBaoNtdt.xml");
    dmDMuc = new DMucDMuc("data\\DMucDMuc.xml");
    dmDKy = new DMucDKy("data\\DMucHSoDky.xml");
    dmHquan = new DMucHquan("data\\DMucHquan.xml");
    dmHquan1 = new DMucHquan1("data\\DMucHquan1.xml");
    dmTBaoKDTT = new DMucTBaoKDTT("data\\DMucTBaoKDTT.xml");
    dmBKeKDTT = new DMucBKeKDTT("data\\DMucBKeKDTT.xml");
    homePageFileName = new File("infor\\homepage\\TaxViewHomePage.htm").toURI().toURL().toString();
    TBaoXpath = "/TBaoThueDTu/TBaoThue";
    DmucXpath = "/DanhMucDTu/DanhMuc";
    DkyXpath = "/DKyThueDTu/DKyThue";
    TBaoNtdtXpath = "/THONGBAO/NDUNG_TBAO";
    rootCerts = CertVerifier.getCertificateList("certstore\\root");
    trustedCerts = CertVerifier.getCertificateList("certstore\\trust");
  }
  
  public DMucDKy getDmDKy() {
    return dmDKy;
  }
  
  public void setDmDKy(DMucDKy dmDKy) {
    this.dmDKy = dmDKy;
  }
  
  public String getDmucXpath() {
    return DmucXpath;
  }
  
  public String getDkyXpath() {
    return DkyXpath;
  }
  
  public String getTBaoNtdtXpath() {
    return TBaoNtdtXpath;
  }
  
  public String getTBaoXpath() {
    return TBaoXpath;
  }
  
  public DMucDMuc getDmDMuc() { return dmDMuc; }
  
  public DMucTBao getDmTBao()
  {
    return dmTBao;
  }
  
  public DMucTBaoNtdt getDmTBaoNtdt() { return dmTBaoNtdt; }
  
  public String getHomePageFileName()
  {
    return homePageFileName;
  }
  
  public DMucTKhai getDmTKhai() { return dmTKhai; }
  
  public DMucCTu getDmCTu() {
    return dmCTu;
  }
  
  public X509Certificate[] getRootCerts() {
    return rootCerts;
  }
  
  public X509Certificate[] getTrustedCerts() { return trustedCerts; }
  
  public DMucHquan getDmHquan()
  {
    return dmHquan;
  }
  
  public void setDmHquan(DMucHquan dmHquan) {
    this.dmHquan = dmHquan;
  }
  
  public DMucHquan1 getDmHquan1() { return dmHquan1; }
  
  public void setDmHquan1(DMucHquan1 dmHquan1)
  {
    this.dmHquan1 = dmHquan1;
  }
  
  public DMucTBaoKDTT getDmTBaoKDTT() {
    return dmTBaoKDTT;
  }
  
  public void setDmTBaoKDTT(DMucTBaoKDTT dmTBaoKDTT) {
    this.dmTBaoKDTT = dmTBaoKDTT;
  }
  
  public DMucBKeKDTT getDmBKeKDTT() {
    return dmBKeKDTT;
  }
  
  public void setDmBKeKDTT(DMucBKeKDTT dmBKeKDTT) {
    this.dmBKeKDTT = dmBKeKDTT;
  }
}
