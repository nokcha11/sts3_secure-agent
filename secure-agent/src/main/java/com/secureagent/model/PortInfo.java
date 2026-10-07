package com.secureagent.model;

public class PortInfo {

    private String protocol;
    private String localAddress;
    private int localPort;
    private String state;
    private long pid;
    private String processName;

    public PortInfo() {
    }

    public PortInfo(String protocol, String localAddress,
                    int localPort, String state,
                    long pid, String processName) {
        this.protocol = protocol;
        this.localAddress = localAddress;
        this.localPort = localPort;
        this.state = state;
        this.pid = pid;
        this.processName = processName;
    }

    public String getProtocol() {
        return protocol;
    }

    public void setProtocol(String protocol) {
        this.protocol = protocol;
    }

    public String getLocalAddress() {
        return localAddress;
    }

    public void setLocalAddress(String localAddress) {
        this.localAddress = localAddress;
    }

    public int getLocalPort() {
        return localPort;
    }

    public void setLocalPort(int localPort) {
        this.localPort = localPort;
    }

    public String getState() {
        return state;
    }

    public void setState(String state) {
        this.state = state;
    }

    public long getPid() {
        return pid;
    }

    public void setPid(long pid) {
        this.pid = pid;
    }

    public String getProcessName() {
        return processName;
    }

    public void setProcessName(String processName) {
        this.processName = processName;
    }

    @Override
    public String toString() {
        return "PortInfo [protocol=" + protocol
                + ", localAddress=" + localAddress
                + ", localPort=" + localPort
                + ", state=" + state
                + ", pid=" + pid
                + ", processName=" + processName + "]";
    }
}