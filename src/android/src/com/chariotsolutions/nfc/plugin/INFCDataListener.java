package com.chariotsolutions.nfc.plugin;

public interface INFCDataListener
{
  void onData(String tag,String data);
}