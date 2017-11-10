package com.sprintwind.packetcapturetool;

//import com.baidu.appx.BDBannerAd;
//import com.baidu.appx.BDBannerAd.BannerAdListener;
//import com.baidu.mobstat.StatService;
import com.sprintwind.packetcapturetool.R;
import android.annotation.TargetApi;
import android.app.Activity;
import android.app.Fragment;
import android.app.FragmentManager;
import android.app.FragmentTransaction;
import android.content.Intent;
import android.os.Build;
import android.os.Bundle;
import android.util.Log;
import android.view.KeyEvent;
import android.view.Menu;
import android.view.MenuItem;
import android.widget.RadioGroup;
import android.widget.RadioGroup.OnCheckedChangeListener;  
import android.widget.RelativeLayout;
import android.widget.Toast;

import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.text.format.Formatter;
import android.view.LayoutInflater;
import java.util.ArrayList;
import java.util.List;

@TargetApi(Build.VERSION_CODES.HONEYCOMB) public class MainActivity extends Activity {
	private Fragment[] fragments;
	private FragmentManager fragmentManager;
	private FragmentTransaction fragmentTransaction;
	
	private RadioGroup rdgrpBottomMenu;
	
	private RelativeLayout appxBannerContainer;
	
	private static final String TAG = "sprintwind";
	
	private long exitTime = 0;
	
	//获取已安装应用的应用名称和UID信息
	private ArrayList<AppTrafficModel> listApps = new ArrayList<AppTrafficModel>();
	
	
	/**
     * 遍历有联网权限的应用程序的流量记录
     */
    private void trafficMonitor(){
        PackageManager pm = this.getPackageManager();
        List<PackageInfo> packinfos = pm.getInstalledPackages(PackageManager.GET_UNINSTALLED_PACKAGES | PackageManager.GET_PERMISSIONS);
        for (PackageInfo info : packinfos) {
            String[] premissions = info.requestedPermissions;
            if (premissions != null && premissions.length > 0) {
                for (String premission : premissions) {
                    if ("android.permission.INTERNET".equals(premission)) {
                        // System.out.println(info.packageName+"访问网络");
                        int uid = info.applicationInfo.uid;
                        String name = pm.getNameForUid(uid);

                        AppTrafficModel appTrafficModel = new AppTrafficModel();
                        appTrafficModel.setAppInfo(info.applicationInfo);
                        appTrafficModel.setUID(uid);
                        appTrafficModel.setAppName(name);
                        
                        String tvname = (String)pm.getApplicationLabel(appTrafficModel.getAppInfo());
                        appTrafficModel.setTvName(tvname);
                        listApps.add(appTrafficModel);
                        System.out.println("appuid:"+appTrafficModel.getUID()+"   appname:"+appTrafficModel.getAppName());
                        Log.i(TAG, "appuid:"+appTrafficModel.getUID()+"   appname:"+appTrafficModel.getAppName());

                    }
                }
            }
        }
    }

    @Override
	public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        
        trafficMonitor();
        int record = JNIgetList(listApps);
        Log.i(TAG, "number:"+record);
        
        fragments = new Fragment[3];  
        fragmentManager = getFragmentManager();  
        fragments[0] = fragmentManager.findFragmentById(R.id.frgmntCapture);  
        fragments[1] = fragmentManager.findFragmentById(R.id.frgmntAnalyze);
        fragments[2] = fragmentManager.findFragmentById(R.id.frgmntMore);

        fragmentTransaction = fragmentManager.beginTransaction()  
                .hide(fragments[0]).hide(fragments[1]).hide(fragments[2]);  
        fragmentTransaction.show(fragments[0]).commit();  
        setFragmentIndicator(); 
        
    }
    
    private void setFragmentIndicator() {  
    	  
        rdgrpBottomMenu = (RadioGroup) findViewById(R.id.rdgrpBottomMenu); 
  
        rdgrpBottomMenu.setOnCheckedChangeListener(new OnCheckedChangeListener() {  
  
            @Override  
            public void onCheckedChanged(RadioGroup group, int checkedId) {  
                fragmentTransaction = fragmentManager.beginTransaction()  
                        .hide(fragments[0]).hide(fragments[1]).hide(fragments[2]);  
                switch (checkedId) {  
                case R.id.rdbttnCapture:  
                    fragmentTransaction.show(fragments[0]).commit();  
                    break;  
  
                case R.id.rdbttnAnalyze:  
                    fragmentTransaction.show(fragments[1]).commit();  
                    break; 
                    
                case R.id.rdbttnMore:
                	fragmentTransaction.show(fragments[2]).commit(); 
                	break;
                default:  
                    break;  
                }  
            }  
        });
    }

    
    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.main, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        int id = item.getItemId();
        if (id == R.id.action_share) {
        	Intent intent=new Intent(Intent.ACTION_SEND);   
            intent.setType("text/*");   
            intent.putExtra(Intent.EXTRA_SUBJECT, "鍒嗕韩");   
            intent.putExtra(Intent.EXTRA_TEXT, getString(R.string.share_string));    
            intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);   
            startActivity(Intent.createChooser(intent, "鍒嗕韩"+getTitle()));
            return true;
        }
        return super.onOptionsItemSelected(item);
    }
    
    /* 鐩戝惉杩斿洖閿寜涓嬩簨浠� */
    @Override
    public boolean onKeyDown(int keyCode, KeyEvent event) {
        if(keyCode == KeyEvent.KEYCODE_BACK && event.getAction() == KeyEvent.ACTION_DOWN){   
            if((System.currentTimeMillis()-exitTime) > 2000){  
                Toast.makeText(getApplicationContext(), getString(R.string.press_to_exit), Toast.LENGTH_SHORT).show();                                
                exitTime = System.currentTimeMillis();   
            } else {
            	/* 鍙栨秷娉ㄥ唽缃戠粶鍙樺寲閫氱煡 */
            	//unregisterReceiver(broadcastReceiver);
                finish();
                System.exit(0);
            }
            return true;   
        }
        return super.onKeyDown(keyCode, event);
    }
    
    public native int JNIgetList(ArrayList<AppTrafficModel> listApps);
    
    static{
    	System.loadLibrary("PacketCaptureTool");
    }
    
}
