package com.secureagent.collector;

import com.secureagent.model.SystemInfo;

public class SystemInfoCollector {

	public SystemInfo collect() {
		
		String computerName = System.getenv("COMPUTERNAME");
		String osName = System.getProperty("os.name");
		String osVersion = System.getProperty("os.version");
		String userName = System.getProperty("user.name");
		
		SystemInfo systemInfo = new SystemInfo(
				computerName,
				osName,
				osVersion,
				userName
		);
		
		return systemInfo;
	}
}