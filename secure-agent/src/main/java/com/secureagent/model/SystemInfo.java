package com.secureagent.model;

import java.util.ArrayList;
import java.util.List;

public class SystemInfo {

    private String computerName;
    private String osName;
    private String osVersion;
    private String userName;
    private List<PortInfo> portList = new ArrayList<>();

    public SystemInfo() {
    }

    public SystemInfo(String computerName, String osName,
            String osVersion, String userName) {

        this.computerName = computerName;
        this.osName = osName;
        this.osVersion = osVersion;
        this.userName = userName;
    }

    public String getComputerName() {
        return computerName;
    }

    public void setComputerName(String computerName) {
        this.computerName = computerName;
    }

    public String getOsName() {
        return osName;
    }

    public void setOsName(String osName) {
        this.osName = osName;
    }

    public String getOsVersion() {
        return osVersion;
    }

    public void setOsVersion(String osVersion) {
        this.osVersion = osVersion;
    }

    public String getUserName() {
        return userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    public List<PortInfo> getPortList() {
        return portList;
    }

    public void setPortList(List<PortInfo> portList) {
        this.portList = portList;
    }
}