package com.chariotsolutions.nfc.plugin;

import android.content.Intent;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.MifareUltralight;
import android.nfc.tech.NfcA;
import android.util.Base64;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import java.io.IOException;


public class AndroidNFCHelper
{
  private NfcA mNfca;
  private INFCDataListener nfcDataListener;

  private byte[] tagSN;
  private byte[] tagData = new byte[80];    // total size to read
  private byte[] tagRnd1 = new byte[8];     // Random 1 (challenge)
  private byte[] tagEkRndR2 = new byte[8];  // Encrypted rotated Rnd2
  private String operation;

  public AndroidNFCHelper(String paramOperation)
  { 
    operation=paramOperation;
  }

  public void setNfcDataListener(INFCDataListener nfcDataListener)
  {
    this.nfcDataListener = nfcDataListener;
  }

  public boolean processTagRead(Intent intent)
  {
    Tag receivedTag;
    boolean foundULC = false;
    int tagBufferSize;

    receivedTag = intent.getParcelableExtra(NfcAdapter.EXTRA_TAG);
    if (receivedTag == null)
      return false;

    tagSN = receivedTag.getId();  // Get serial number (in bytes)
    mNfca = null;

    // Search tag tech info list for Mifare Ultralight C and NfcA compliant tag. Both must be met.
    for (String techInfo : receivedTag.getTechList()) {
      if (techInfo.equals(MifareUltralight.class.getName())) {
        foundULC = true;
      }	else if (techInfo.equals(NfcA.class.getName())) {
        mNfca = NfcA.get(receivedTag);  // Get tag as NfcA
        tagBufferSize = mNfca.getMaxTransceiveLength(); // Get max buffer
        if (tagBufferSize < 16) {
          // Optional test: This should not happen, but if it does it means something is wrong. Read returns 4 pages = 16 bytes. Buffer must be large enough.
          //Log.e(MainActivity.TAG, "Buffer needs to have 16 bytes of minimum size");
          return false;
        }
      }
    }

    if (!foundULC || mNfca == null) {
      //Log.e(MainActivity.TAG, "Invalid tag");
      return false;
    }

    // Read data
    if (!loadDataFromTag()) {
      //Log.e(MainActivity.TAG, "Failed to read tag");
      return false;
    }

    nfcDataListener.onData(getHexSN(),buildJsonString());

    return true;
  }

  public boolean processTagWrite(Intent intent, int newBalance)
  {

    Tag receivedTag;
    JSONObject jsonRequest;

    // Will skip the validations used for Read
    receivedTag = intent.getParcelableExtra(NfcAdapter.EXTRA_TAG);
    tagSN = receivedTag.getId();
    mNfca = NfcA.get(receivedTag);
    mNfca.setTimeout(2000);
    // Read data
    if (!loadDataFromTag(true)) {

      //Log.e(MainActivity.TAG, "Failed to read tag");
      return false;
    }

    if (!startAuthentication()) {
      //Log.e(MainActivity.TAG, "Failed to start authentication");
      return false;
    }

    try {

      jsonRequest = new JSONObject();
      jsonRequest.put("request_type", 2);  // 2 for card write
      jsonRequest.put("operation_id", operation);
      jsonRequest.put("serial_number", getHexSN());
      jsonRequest.put("card_data", getBase64Data());
      jsonRequest.put("expiration_date", 0);
      jsonRequest.put("new_balance", newBalance);
      jsonRequest.put("rnd_1", getBase64Rnd1());
      nfcDataListener.onData(getHexSN(),jsonRequest.toString());
    } catch (Exception e) {}

    return true;
  }

  public boolean confirmAuthentication(String base64EkRnd2_RndR1, String base64EkRndR2)
  {
    byte ekRnd2_RndR1[];
    byte pkgResponse[];
    byte ekRndR2[] = new byte[8];
    byte authPhase2Command[] = new byte[17];
    String base64EkRndR2_Response;

    ekRnd2_RndR1 = Base64.decode(base64EkRnd2_RndR1, Base64.NO_WRAP | Base64.URL_SAFE);
    authPhase2Command[0] = (byte) 0xAF;
    System.arraycopy(ekRnd2_RndR1, 0, authPhase2Command, 1, 16);
    //MainActivity.DebugBinaryData("ekRnd2_RndR1", ekRnd2_RndR1);

    try {
      pkgResponse = mNfca.transceive(authPhase2Command);
    } catch (Exception e) {
      e.printStackTrace();
      try {
        mNfca.close();
      } catch (Exception foo) {}
      return false;
    }
    if (pkgResponse[0] != 0x00 || pkgResponse.length < 9) {
      try {
        mNfca.close();
      } catch (Exception foo) {}
      //Log.e(MainActivity.TAG,"BAD DATA ON TRANSCEIVE - Authentication command");
      return false;
    }
    System.arraycopy(pkgResponse, 1, ekRndR2, 0, 8);
    base64EkRndR2_Response = Base64.encodeToString(ekRndR2, Base64.NO_WRAP);
    if (!base64EkRndR2.equals(base64EkRndR2_Response)) {
      //Log.e(MainActivity.TAG, "RND2 DOES NOT MATCH!!!");
      try {
        mNfca.close();
      } catch (Exception foo) {}
      return false;
    }

    // Keep connection alive for writing data
    return true;
  }

  public boolean writeNewDataIntoTag(String cardData)
  {
    byte nfcMemoryPage;
    byte writeCommand[] = { (byte) 0xA2 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 };
    int dataIndex, i;
    byte foo_data[];

    tagData = Base64.decode(cardData, Base64.NO_WRAP | Base64.URL_SAFE);

    dataIndex = 0;
    // Read from page 0x08 to page 0x1B (80 bytes of data / 20 memory pages)
    for (nfcMemoryPage = 0x08; nfcMemoryPage < 0x1C; nfcMemoryPage++) {
      // We can only write one page at a time (4 bytes)
      writeCommand[1] = nfcMemoryPage;
      System.arraycopy(tagData, dataIndex, writeCommand, 2, 4);
      dataIndex += 4;
      try {
        foo_data = mNfca.transceive(writeCommand);
        //MainActivity.DebugBinaryData("page_" + nfcMemoryPage, foo_data);
      } catch (Exception e) {
        e.printStackTrace();
        try {
          mNfca.close();
        } catch (Exception foo) {}
        return false;
      }
    }

    try {
      mNfca.close();
    } catch (Exception foo) {}
    return true;
  }

  private boolean loadDataFromTag()
  {
    return loadDataFromTag(false);
  }

  private boolean loadDataFromTag(boolean keepConnectionOpened)
  {
    byte nfcMemoryPage;
    int  dataIndex, dataRead;
    byte readCommand[] = { 0x30 , 0x00 }; // 0x30 is the command for READ followed by the page number
    byte[] tagBuffer;

    // Clear tagData array
    for (dataIndex = 0; dataIndex < 80; dataIndex++)
      tagData[dataIndex] = 0x00;

    dataIndex = 0;

    try {
      mNfca.connect();
    } catch (IOException ioError) {
      //Log.e(MainActivity.TAG, "Error opening tag: " + ioError.getMessage());
      return false;
    }

    // Read from page 0x08 to page 0x1B (80 bytes of data / 20 memory pages)
    for (nfcMemoryPage = 0x08; nfcMemoryPage < 0x1B; nfcMemoryPage += 4) {
      // We can read up to 4 pages each time (16 bytes)
      readCommand[1] = nfcMemoryPage;
      try {
        tagBuffer = mNfca.transceive(readCommand);
      }
      catch (IOException ioError) {
        //Log.e(MainActivity.TAG, "IOException reading NFC tag: " + ioError.getMessage());
        return false;
      }
      // We must have read 16 bytes. It should not return more than 16 either but we will skip that here
      dataRead = tagBuffer.length;
      if (dataRead < 16) {
        //Log.e(MainActivity.TAG, "Error reading data. Only " + dataRead + " bytes were read");
        return false;
      }
      // Copy to buffer
      System.arraycopy(tagBuffer, 0, tagData, dataIndex, 16);
      dataIndex += 16;
    }

    if (keepConnectionOpened)
      return true;

    try {
      mNfca.close();
    } catch (IOException ioError) {
      //Log.e(MainActivity.TAG, "Error closing tag: " + ioError.getMessage());
      return false;
    }

    return true;
  }

  private boolean startAuthentication()
  {
    byte authCommand[] = { 0x1A, 0x00 };
    byte tagChallenge[];

    for (int i = 0; i < 8; i++)
      tagRnd1[i] = 0;

    try {
      tagChallenge = mNfca.transceive(authCommand);
      if (tagChallenge[0] != (byte) 0xAF || tagChallenge.length < 9)
        return false;
      System.arraycopy(tagChallenge, 1, tagRnd1, 0, 8);
    } catch (Exception e) {
      e.printStackTrace();
      return false;
    }
    //MainActivity.DebugBinaryData("rnd1", tagRnd1);
    // KEEP CONNECTION OPEN OR AUTHENTICATION PROCESS WILL DROP
    return true;
  }

  private String buildJsonString()
  {

    JSONObject jsonObject;

    jsonObject = new JSONObject();
    String out = getBase64Data();

    try {
      jsonObject.put("request_type", 1);  // 1 for Get card data
      jsonObject.put("serial_number", getHexSN());
      jsonObject.put("operation_id",operation);
      jsonObject.put("card_data", out);
    } catch (Exception e) {
      //Log.e(MainActivity.TAG, "JSON OBJECT ERROR: " + e.getMessage());
      e.printStackTrace();
    }


    return jsonObject.toString();
  }

  private String getHexSN()
  {
    int i;
    String hexSN = "";

    // SN is big endian
    for (i = tagSN.length - 1; i >= 0; i--)
      hexSN += String.format("%02X", tagSN[i]);

    return hexSN;
  }

  private String getBase64Data()
  {

    return Base64.encodeToString(tagData, Base64.NO_WRAP | Base64.URL_SAFE);
  }

  private String getBase64Rnd1()
  {
    return Base64.encodeToString(tagRnd1, Base64.NO_WRAP | Base64.URL_SAFE);
  }
}
