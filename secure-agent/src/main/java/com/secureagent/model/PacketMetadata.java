package com.secureagent.model;

public class PacketMetadata {

    /*
     * TCP 또는 UDP
     */
    private String protocol;

    /*
     * DNS, HTTP, HTTPS, OTHER
     */
    private String applicationProtocol;

    /*
     * INBOUND: 수신
     * OUTBOUND: 송신
     */
    private String direction;

    /*
     * 현재 PC의 IP와 포트
     */
    private String localAddress;
    private int localPort;

    /*
     * 통신 상대방의 IP와 포트
     */
    private String remoteAddress;
    private int remotePort;

    /*
     * 동일한 통신에서 수집된 패킷 수와
     * 전체 패킷 크기
     */
    private long packetCount;
    private long totalBytes;

    /*
     * 최초 수집 시각과 마지막 수집 시각
     */
    private String firstSeenAt;
    private String lastSeenAt;

    /*
     * 상대방 IP가 외부 공인 IP인지 표시
     */
    private String externalYn;

    /*
     * DNS 패킷에서 확인한 도메인
     */
    private String dnsDomain;

    /*
     * 암호화되지 않은 HTTP 요청의 Host 값
     */
    private String httpHost;

    /*
     * HTTPS TLS ClientHello에서 확인한
     * SNI 서버 도메인입니다.
     *
     * HTTPS 본문을 복호화하지 않고
     * 공개된 연결 메타데이터만 저장합니다.
     */
    private String tlsServerName;

    public PacketMetadata() {
    }

    /*
     * 기존 PacketMetadataCollector와의 호환을 위해
     * 기존 생성자 구조를 그대로 유지합니다.
     */
    public PacketMetadata(
            String protocol,
            String applicationProtocol,
            String direction,
            String localAddress,
            int localPort,
            String remoteAddress,
            int remotePort,
            int packetSize,
            String capturedAt,
            String externalYn,
            String dnsDomain,
            String httpHost) {

        this.protocol = protocol;
        this.applicationProtocol =
                applicationProtocol;
        this.direction = direction;
        this.localAddress = localAddress;
        this.localPort = localPort;
        this.remoteAddress = remoteAddress;
        this.remotePort = remotePort;

        this.packetCount = 1;
        this.totalBytes = Math.max(
                packetSize,
                0
        );

        this.firstSeenAt = capturedAt;
        this.lastSeenAt = capturedAt;

        this.externalYn = externalYn;
        this.dnsDomain = dnsDomain;
        this.httpHost = httpHost;
        this.tlsServerName = null;
    }

    public void addPacket(
            int packetSize,
            String capturedAt) {

        this.packetCount++;

        this.totalBytes += Math.max(
                packetSize,
                0
        );

        this.lastSeenAt = capturedAt;
    }

    public String createAggregationKey() {

        return safe(protocol)
                + "|"
                + safe(direction)
                + "|"
                + safe(localAddress)
                + "|"
                + localPort
                + "|"
                + safe(remoteAddress)
                + "|"
                + remotePort
                + "|"
                + safe(dnsDomain)
                + "|"
                + safe(httpHost)
                + "|"
                + safe(tlsServerName);
    }

    private String safe(String value) {

        return value == null
                ? ""
                : value;
    }

    public String getProtocol() {
        return protocol;
    }

    public void setProtocol(String protocol) {
        this.protocol = protocol;
    }

    public String getApplicationProtocol() {
        return applicationProtocol;
    }

    public void setApplicationProtocol(
            String applicationProtocol) {

        this.applicationProtocol =
                applicationProtocol;
    }

    public String getDirection() {
        return direction;
    }

    public void setDirection(String direction) {
        this.direction = direction;
    }

    public String getLocalAddress() {
        return localAddress;
    }

    public void setLocalAddress(
            String localAddress) {

        this.localAddress = localAddress;
    }

    public int getLocalPort() {
        return localPort;
    }

    public void setLocalPort(int localPort) {
        this.localPort = localPort;
    }

    public String getRemoteAddress() {
        return remoteAddress;
    }

    public void setRemoteAddress(
            String remoteAddress) {

        this.remoteAddress = remoteAddress;
    }

    public int getRemotePort() {
        return remotePort;
    }

    public void setRemotePort(int remotePort) {
        this.remotePort = remotePort;
    }

    public long getPacketCount() {
        return packetCount;
    }

    public void setPacketCount(
            long packetCount) {

        this.packetCount = packetCount;
    }

    public long getTotalBytes() {
        return totalBytes;
    }

    public void setTotalBytes(
            long totalBytes) {

        this.totalBytes = totalBytes;
    }

    public String getFirstSeenAt() {
        return firstSeenAt;
    }

    public void setFirstSeenAt(
            String firstSeenAt) {

        this.firstSeenAt = firstSeenAt;
    }

    public String getLastSeenAt() {
        return lastSeenAt;
    }

    public void setLastSeenAt(
            String lastSeenAt) {

        this.lastSeenAt = lastSeenAt;
    }

    public String getExternalYn() {
        return externalYn;
    }

    public void setExternalYn(
            String externalYn) {

        this.externalYn = externalYn;
    }

    public String getDnsDomain() {
        return dnsDomain;
    }

    public void setDnsDomain(
            String dnsDomain) {

        this.dnsDomain = dnsDomain;
    }

    public String getHttpHost() {
        return httpHost;
    }

    public void setHttpHost(
            String httpHost) {

        this.httpHost = httpHost;
    }

    public String getTlsServerName() {
        return tlsServerName;
    }

    public void setTlsServerName(
            String tlsServerName) {

        this.tlsServerName =
                tlsServerName;
    }

    @Override
    public String toString() {

        return "PacketMetadata{"
                + "protocol='"
                + protocol
                + '\''
                + ", applicationProtocol='"
                + applicationProtocol
                + '\''
                + ", direction='"
                + direction
                + '\''
                + ", localAddress='"
                + localAddress
                + '\''
                + ", localPort="
                + localPort
                + ", remoteAddress='"
                + remoteAddress
                + '\''
                + ", remotePort="
                + remotePort
                + ", packetCount="
                + packetCount
                + ", totalBytes="
                + totalBytes
                + ", firstSeenAt='"
                + firstSeenAt
                + '\''
                + ", lastSeenAt='"
                + lastSeenAt
                + '\''
                + ", externalYn='"
                + externalYn
                + '\''
                + ", dnsDomain='"
                + dnsDomain
                + '\''
                + ", httpHost='"
                + httpHost
                + '\''
                + ", tlsServerName='"
                + tlsServerName
                + '\''
                + '}';
    }
}
