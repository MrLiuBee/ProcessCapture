package com.sprintwind.packetcapturetool;

import android.content.pm.ApplicationInfo;
import java.io.Serializable;

/**
 * 记录应用程序流量的model
 * Created by changhuiliu on 2017/4/23.
 */
public class AppTrafficModel {
	private ApplicationInfo appInfo;
    int uid;
    String appname;
    String tvname;
    
    public String getTvName(){
    	return tvname;
    }
    
    public void setTvName(String tvname){
    	this.tvname = tvname;
    }

    public int getUID(){
    	return uid;
    }
    
    public void setUID(int uid){
    	this.uid = uid;
    }
    
    public String getAppName(){
    	return appname;
    }
    
    public void setAppName(String appname){
    	this.appname = appname;
    }


    public ApplicationInfo getAppInfo() {
        return appInfo;
    }

    public void setAppInfo(ApplicationInfo appInfo) {
        this.appInfo = appInfo;
    }
}
