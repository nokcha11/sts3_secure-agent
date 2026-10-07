package com.secureagent.collector;

import java.io.EOFException;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapAddress;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV6Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;

import com.secureagent.model.PacketMetadata;

public class PacketMetadataCollector {

    private static final int CAPTURE_SECONDS = 10;

    private static final int MAX_PACKET_COUNT = 5000;

    private static final int SNAPSHOT_LENGTH = 65536;

    private static final int READ_TIMEOUT_MILLISECONDS = 100;

    private static final int IP_PROTOCOL_TCP = 6;

    private static final int IP_PROTOCOL_UDP = 17;

    private static final int ETHER_TYPE_IPV4 = 0x0800;

    private static final int ETHER_TYPE_IPV6 = 0x86dd;

    private static final int ETHER_TYPE_VLAN = 0x8100;

    private static final int ETHER_TYPE_PROVIDER_VLAN =
            0x88a8;

    private static final DateTimeFormatter TIME_FORMATTER =
            DateTimeFormatter.ISO_LOCAL_DATE_TIME;

    private final DnsDomainExtractor
            dnsDomainExtractor =
                    new DnsDomainExtractor();

    private final HttpHostExtractor
            httpHostExtractor =
                    new HttpHostExtractor();

    private final TlsSniExtractor
            tlsSniExtractor =
                    new TlsSniExtractor();

    /*
     * Pcap4J의 일반 객체 변환에 실패하여
     * 원시 데이터 보조 해석을 사용한 패킷 수입니다.
     */
    private int rawFallbackPacketCount;

    public List<PacketMetadata> collect() {

        configureNpcapLibraries();

        rawFallbackPacketCount = 0;

        Map<String, PacketMetadata> metadataMap =
                new LinkedHashMap<>();

        PcapHandle handle = null;

        int capturedPacketCount = 0;

        try {
            PcapNetworkInterface device =
                    findCaptureDevice();

            if (device == null) {
                System.err.println(
                        "패킷을 수집할 실제 네트워크 "
                                + "장치를 찾지 못했습니다."
                );

                return new ArrayList<>();
            }

            Set<String> localAddresses =
                    getLocalAddresses(device);

            System.out.println(
                    "패킷 수집 장치: "
                            + device.getDescription()
            );

            System.out.println(
                    "패킷 수집 IP: "
                            + String.join(
                                    ", ",
                                    localAddresses
                            )
            );

            handle = device.openLive(
                    SNAPSHOT_LENGTH,
                    PromiscuousMode.NONPROMISCUOUS,
                    READ_TIMEOUT_MILLISECONDS
            );

            handle.setFilter(
                    "tcp or udp",
                    BpfCompileMode.OPTIMIZE
            );

            System.out.println(
                    "패킷 캡처 준비가 완료되었습니다."
            );

            System.out.println(
                    "패킷 메타데이터를 "
                            + CAPTURE_SECONDS
                            + "초 동안 수집합니다."
            );

            long captureEndTime =
                    System.nanoTime()
                            + TimeUnit.SECONDS.toNanos(
                                    CAPTURE_SECONDS
                            );

            while (
                System.nanoTime() < captureEndTime
                        && capturedPacketCount
                            < MAX_PACKET_COUNT
            ) {
                try {
                    Packet packet =
                            handle.getNextPacketEx();

                    capturedPacketCount++;

                    String capturedAt =
                            getCapturedAt(handle);

                    PacketMetadata metadata =
                            convertToMetadata(
                                    packet,
                                    localAddresses,
                                    capturedAt
                            );

                    if (metadata == null) {
                        continue;
                    }

                    mergeMetadata(
                            metadataMap,
                            metadata,
                            packet.length(),
                            capturedAt
                    );

                } catch (TimeoutException e) {

                    continue;

                } catch (EOFException e) {

                    break;
                }
            }

        } catch (PcapNativeException e) {

            System.err.println(
                    "Npcap 패킷 수집 중 오류가 발생했습니다."
            );

            System.err.println(
                    "오류 내용: "
                            + e.getMessage()
            );

        } catch (NotOpenException e) {

            System.err.println(
                    "패킷 캡처 장치가 열려 있지 않습니다."
            );

            System.err.println(
                    "오류 내용: "
                            + e.getMessage()
            );

        } finally {

            if (handle != null) {
                handle.close();
            }
        }

        List<PacketMetadata> metadataList =
                new ArrayList<>(
                        metadataMap.values()
                );

        metadataList.sort(
                Comparator.comparingLong(
                        PacketMetadata::getPacketCount
                ).reversed()
        );

        System.out.println(
                "수집된 원본 패킷 수: "
                        + capturedPacketCount
        );

        System.out.println(
                "통신별로 합친 메타데이터 수: "
                        + metadataList.size()
        );

        System.out.println(
                "원시 패킷 보조 해석 수: "
                        + rawFallbackPacketCount
        );

        long dnsMetadataCount =
                metadataList.stream()
                        .filter(
                                metadata ->
                                    "DNS".equals(
                                            metadata
                                                .getApplicationProtocol()
                                    )
                        )
                        .count();

        System.out.println(
                "DNS 통신 메타데이터 수: "
                        + dnsMetadataCount
        );

        long dnsDomainCount =
                metadataList.stream()
                        .filter(
                                metadata ->
                                    metadata.getDnsDomain()
                                        != null
                                        && !metadata
                                            .getDnsDomain()
                                            .isBlank()
                        )
                        .count();

        System.out.println(
                "DNS 도메인이 확인된 메타데이터 수: "
                        + dnsDomainCount
        );

        long httpHostCount =
                metadataList.stream()
                        .filter(
                                metadata ->
                                    metadata.getHttpHost()
                                        != null
                                        && !metadata
                                            .getHttpHost()
                                            .isBlank()
                        )
                        .count();

        System.out.println(
                "HTTP Host가 확인된 메타데이터 수: "
                        + httpHostCount
        );

        long tlsSniCount =
                metadataList.stream()
                        .filter(
                                metadata ->
                                    metadata.getTlsServerName()
                                        != null
                                        && !metadata
                                            .getTlsServerName()
                                            .isBlank()
                        )
                        .count();

        System.out.println(
                "TLS SNI가 확인된 메타데이터 수: "
                        + tlsSniCount
        );

        return metadataList;
    }

    private void mergeMetadata(
            Map<String, PacketMetadata> metadataMap,
            PacketMetadata newMetadata,
            int packetSize,
            String capturedAt) {

        String key =
                newMetadata.createAggregationKey();

        PacketMetadata savedMetadata =
                metadataMap.get(key);

        if (savedMetadata == null) {

            metadataMap.put(
                    key,
                    newMetadata
            );

            return;
        }

        savedMetadata.addPacket(
                packetSize,
                capturedAt
        );
    }

    private PacketMetadata convertToMetadata(
            Packet packet,
            Set<String> localAddresses,
            String capturedAt) {

        TransportInfo transportInfo =
                extractTransportInfo(packet);

        if (transportInfo == null) {
            return null;
        }

        String sourceAddress =
                transportInfo.sourceAddress;

        String destinationAddress =
                transportInfo.destinationAddress;

        String protocol =
                transportInfo.protocol;

        int sourcePort =
                transportInfo.sourcePort;

        int destinationPort =
                transportInfo.destinationPort;

        String direction;
        String localAddress;
        int localPort;
        String remoteAddress;
        int remotePort;

        if (localAddresses.contains(sourceAddress)) {

            direction = "OUTBOUND";

            localAddress = sourceAddress;
            localPort = sourcePort;

            remoteAddress = destinationAddress;
            remotePort = destinationPort;

        } else if (
            localAddresses.contains(
                    destinationAddress
            )
        ) {

            direction = "INBOUND";

            localAddress = destinationAddress;
            localPort = destinationPort;

            remoteAddress = sourceAddress;
            remotePort = sourcePort;

        } else {

            return null;
        }

        String applicationProtocol =
                detectApplicationProtocol(
                        localPort,
                        remotePort
                );

        String externalYn =
                isExternalAddress(remoteAddress)
                        ? "Y"
                        : "N";

        String dnsDomain = null;

        if ("DNS".equals(applicationProtocol)) {

            /*
             * Pcap4J가 DnsPacket까지 정상 변환한 경우에는
             * 기존 추출기로 도메인을 가져옵니다.
             *
             * 원시 패킷의 DNS 도메인 추출은
             * 다음 단계에서 DnsDomainExtractor에 추가합니다.
             */
            dnsDomain =
                    dnsDomainExtractor.extract(
                            packet
                    );
        }

        String httpHost = null;

        if ("HTTP".equals(applicationProtocol)) {

            httpHost =
                    httpHostExtractor.extract(
                            packet
                    );
        }

        String tlsServerName = null;

        if ("HTTPS".equals(applicationProtocol)) {

            tlsServerName =
                    tlsSniExtractor.extract(
                            packet
                    );
        }

        PacketMetadata metadata =
                new PacketMetadata(
                        protocol,
                        applicationProtocol,
                        direction,
                        localAddress,
                        localPort,
                        remoteAddress,
                        remotePort,
                        packet.length(),
                        capturedAt,
                        externalYn,
                        dnsDomain,
                        httpHost
                );

        metadata.setTlsServerName(
                tlsServerName
        );

        return metadata;
    }

    /*
     * 먼저 Pcap4J가 생성한 TCP·UDP 객체를 사용합니다.
     *
     * 변환에 실패했다면 원시 패킷 데이터를
     * 보조적으로 해석합니다.
     */
    private TransportInfo extractTransportInfo(
            Packet packet) {

        TransportInfo pcapTransportInfo =
                extractPcapTransportInfo(
                        packet
                );

        if (pcapTransportInfo != null) {
            return pcapTransportInfo;
        }

        TransportInfo rawTransportInfo =
                extractRawTransportInfo(
                        packet
                );

        if (rawTransportInfo != null) {
            rawFallbackPacketCount++;
        }

        return rawTransportInfo;
    }

    /*
     * Pcap4J가 정상적으로 만든 IP·TCP·UDP 객체에서
     * 주소와 포트를 가져옵니다.
     */
    private TransportInfo extractPcapTransportInfo(
            Packet packet) {

        IpV4Packet ipV4Packet =
                packet.get(IpV4Packet.class);

        IpV6Packet ipV6Packet =
                packet.get(IpV6Packet.class);

        String sourceAddress;
        String destinationAddress;

        if (ipV4Packet != null) {

            sourceAddress =
                    ipV4Packet
                        .getHeader()
                        .getSrcAddr()
                        .getHostAddress();

            destinationAddress =
                    ipV4Packet
                        .getHeader()
                        .getDstAddr()
                        .getHostAddress();

        } else if (ipV6Packet != null) {

            sourceAddress =
                    ipV6Packet
                        .getHeader()
                        .getSrcAddr()
                        .getHostAddress();

            destinationAddress =
                    ipV6Packet
                        .getHeader()
                        .getDstAddr()
                        .getHostAddress();

        } else {

            return null;
        }

        TcpPacket tcpPacket =
                packet.get(TcpPacket.class);

        if (tcpPacket != null) {

            return new TransportInfo(
                    "TCP",
                    sourceAddress,
                    destinationAddress,
                    tcpPacket
                        .getHeader()
                        .getSrcPort()
                        .valueAsInt(),
                    tcpPacket
                        .getHeader()
                        .getDstPort()
                        .valueAsInt()
            );
        }

        UdpPacket udpPacket =
                packet.get(UdpPacket.class);

        if (udpPacket != null) {

            return new TransportInfo(
                    "UDP",
                    sourceAddress,
                    destinationAddress,
                    udpPacket
                        .getHeader()
                        .getSrcPort()
                        .valueAsInt(),
                    udpPacket
                        .getHeader()
                        .getDstPort()
                        .valueAsInt()
            );
        }

        return null;
    }

    /*
     * Pcap4J 객체 변환이 실패한 패킷에서
     * Ethernet과 IP 헤더의 최소 정보만 확인합니다.
     *
     * 원시 패킷은 메모리에서 잠시 분석할 뿐
     * 파일이나 DB에 저장하지 않습니다.
     */
    private TransportInfo extractRawTransportInfo(
            Packet packet) {

        if (packet == null) {
            return null;
        }

        byte[] rawData =
                packet.getRawData();

        if (rawData == null
                || rawData.length < 1) {

            return null;
        }

        int ipOffset =
                findIpOffset(rawData);

        if (ipOffset < 0
                || ipOffset >= rawData.length) {

            return null;
        }

        int ipVersion =
                (rawData[ipOffset] >> 4)
                        & 0x0f;

        if (ipVersion == 4) {

            return extractRawIpv4TransportInfo(
                    rawData,
                    ipOffset
            );
        }

        if (ipVersion == 6) {

            return extractRawIpv6TransportInfo(
                    rawData,
                    ipOffset
            );
        }

        return null;
    }

    /*
     * Ethernet 프레임에서 IP 패킷이 시작하는
     * 위치를 확인합니다.
     */
    private int findIpOffset(
            byte[] rawData) {

        /*
         * Ethernet 헤더 없이 IP 패킷만 전달된 경우
         */
        int firstVersion =
                (rawData[0] >> 4)
                        & 0x0f;

        if (firstVersion == 4
                || firstVersion == 6) {

            return 0;
        }

        /*
         * 일반 Ethernet 헤더는 14바이트입니다.
         */
        if (rawData.length < 14) {
            return -1;
        }

        int etherType =
                readUnsignedShort(
                        rawData,
                        12
                );

        int payloadOffset = 14;

        /*
         * VLAN 태그가 있으면 다음 EtherType까지
         * 4바이트씩 이동합니다.
         */
        while (
            etherType == ETHER_TYPE_VLAN
                    || etherType
                        == ETHER_TYPE_PROVIDER_VLAN
        ) {
            if (rawData.length
                    < payloadOffset + 4) {

                return -1;
            }

            etherType =
                    readUnsignedShort(
                            rawData,
                            payloadOffset + 2
                    );

            payloadOffset += 4;
        }

        if (etherType == ETHER_TYPE_IPV4
                || etherType == ETHER_TYPE_IPV6) {

            return payloadOffset;
        }

        return -1;
    }

    private TransportInfo
            extractRawIpv4TransportInfo(
                    byte[] rawData,
                    int ipOffset) {

        if (rawData.length
                < ipOffset + 20) {

            return null;
        }

        int headerLength =
                (rawData[ipOffset] & 0x0f)
                        * 4;

        if (headerLength < 20
                || rawData.length
                    < ipOffset + headerLength) {

            return null;
        }

        /*
         * 두 번째 이후 조각에는 TCP·UDP 헤더가 없으므로
         * 안전하게 제외합니다.
         */
        int fragmentInfo =
                readUnsignedShort(
                        rawData,
                        ipOffset + 6
                );

        int fragmentOffset =
                fragmentInfo & 0x1fff;

        if (fragmentOffset != 0) {
            return null;
        }

        int protocolNumber =
                rawData[ipOffset + 9]
                        & 0xff;

        if (protocolNumber != IP_PROTOCOL_TCP
                && protocolNumber
                    != IP_PROTOCOL_UDP) {

            return null;
        }

        int transportOffset =
                ipOffset + headerLength;

        if (rawData.length
                < transportOffset + 4) {

            return null;
        }

        String sourceAddress =
                createAddressText(
                        rawData,
                        ipOffset + 12,
                        4
                );

        String destinationAddress =
                createAddressText(
                        rawData,
                        ipOffset + 16,
                        4
                );

        if (sourceAddress == null
                || destinationAddress == null) {

            return null;
        }

        int sourcePort =
                readUnsignedShort(
                        rawData,
                        transportOffset
                );

        int destinationPort =
                readUnsignedShort(
                        rawData,
                        transportOffset + 2
                );

        String protocol =
                protocolNumber == IP_PROTOCOL_TCP
                        ? "TCP"
                        : "UDP";

        return new TransportInfo(
                protocol,
                sourceAddress,
                destinationAddress,
                sourcePort,
                destinationPort
        );
    }

    private TransportInfo
            extractRawIpv6TransportInfo(
                    byte[] rawData,
                    int ipOffset) {

        if (rawData.length
                < ipOffset + 40) {

            return null;
        }

        int nextHeader =
                rawData[ipOffset + 6]
                        & 0xff;

        int transportOffset =
                ipOffset + 40;

        /*
         * 자주 사용되는 IPv6 확장 헤더를 건너뜁니다.
         */
        for (int count = 0;
                count < 8;
                count++) {

            if (
                nextHeader == 0
                        || nextHeader == 43
                        || nextHeader == 60
            ) {
                if (rawData.length
                        < transportOffset + 2) {

                    return null;
                }

                int newNextHeader =
                        rawData[transportOffset]
                                & 0xff;

                int extensionLength =
                        (
                            (
                                rawData[
                                    transportOffset + 1
                                ] & 0xff
                            ) + 1
                        ) * 8;

                if (extensionLength < 8
                        || rawData.length
                            < transportOffset
                                + extensionLength) {

                    return null;
                }

                nextHeader = newNextHeader;
                transportOffset += extensionLength;

                continue;
            }

            /*
             * IPv6 Fragment Header
             */
            if (nextHeader == 44) {

                if (rawData.length
                        < transportOffset + 8) {

                    return null;
                }

                int fragmentField =
                        readUnsignedShort(
                                rawData,
                                transportOffset + 2
                        );

                int fragmentOffset =
                        (fragmentField & 0xfff8)
                                >> 3;

                if (fragmentOffset != 0) {
                    return null;
                }

                nextHeader =
                        rawData[transportOffset]
                                & 0xff;

                transportOffset += 8;

                continue;
            }

            /*
             * IPv6 Authentication Header
             */
            if (nextHeader == 51) {

                if (rawData.length
                        < transportOffset + 2) {

                    return null;
                }

                int newNextHeader =
                        rawData[transportOffset]
                                & 0xff;

                int extensionLength =
                        (
                            (
                                rawData[
                                    transportOffset + 1
                                ] & 0xff
                            ) + 2
                        ) * 4;

                if (extensionLength < 8
                        || rawData.length
                            < transportOffset
                                + extensionLength) {

                    return null;
                }

                nextHeader = newNextHeader;
                transportOffset += extensionLength;

                continue;
            }

            break;
        }

        if (nextHeader != IP_PROTOCOL_TCP
                && nextHeader
                    != IP_PROTOCOL_UDP) {

            return null;
        }

        if (rawData.length
                < transportOffset + 4) {

            return null;
        }

        String sourceAddress =
                createAddressText(
                        rawData,
                        ipOffset + 8,
                        16
                );

        String destinationAddress =
                createAddressText(
                        rawData,
                        ipOffset + 24,
                        16
                );

        if (sourceAddress == null
                || destinationAddress == null) {

            return null;
        }

        int sourcePort =
                readUnsignedShort(
                        rawData,
                        transportOffset
                );

        int destinationPort =
                readUnsignedShort(
                        rawData,
                        transportOffset + 2
                );

        String protocol =
                nextHeader == IP_PROTOCOL_TCP
                        ? "TCP"
                        : "UDP";

        return new TransportInfo(
                protocol,
                sourceAddress,
                destinationAddress,
                sourcePort,
                destinationPort
        );
    }

    private int readUnsignedShort(
            byte[] rawData,
            int offset) {

        if (offset < 0
                || rawData.length
                    < offset + 2) {

            return -1;
        }

        return (
            (rawData[offset] & 0xff) << 8
        ) | (
            rawData[offset + 1] & 0xff
        );
    }

    private String createAddressText(
            byte[] rawData,
            int offset,
            int length) {

        if (offset < 0
                || length <= 0
                || rawData.length
                    < offset + length) {

            return null;
        }

        try {
            byte[] addressBytes =
                    Arrays.copyOfRange(
                            rawData,
                            offset,
                            offset + length
                    );

            return InetAddress
                    .getByAddress(addressBytes)
                    .getHostAddress();

        } catch (Exception e) {

            return null;
        }
    }

    private String detectApplicationProtocol(
            int localPort,
            int remotePort) {

        if (localPort == 53
                || remotePort == 53) {

            return "DNS";
        }

        if (
            localPort == 80
                    || remotePort == 80
                    || localPort == 8080
                    || remotePort == 8080
        ) {
            return "HTTP";
        }

        if (
            localPort == 443
                    || remotePort == 443
                    || localPort == 8443
                    || remotePort == 8443
        ) {
            return "HTTPS";
        }

        return "OTHER";
    }

    private String getCapturedAt(
            PcapHandle handle) {

        Timestamp timestamp =
                handle.getTimestamp();

        LocalDateTime capturedAt =
                timestamp == null
                        ? LocalDateTime.now()
                        : timestamp.toLocalDateTime();

        return capturedAt.format(
                TIME_FORMATTER
        );
    }

    private PcapNetworkInterface
            findCaptureDevice()
            throws PcapNativeException {

        List<PcapNetworkInterface> devices =
                Pcaps.findAllDevs();

        if (devices == null) {
            return null;
        }

        for (PcapNetworkInterface device : devices) {

            String deviceName =
                    device.getName() == null
                            ? ""
                            : device.getName()
                                .toLowerCase(
                                        Locale.ROOT
                                );

            String description =
                    device.getDescription() == null
                            ? ""
                            : device.getDescription()
                                .toLowerCase(
                                        Locale.ROOT
                                );

            if (
                deviceName.contains("loopback")
                        || description.contains("miniport")
            ) {
                continue;
            }

            for (
                PcapAddress pcapAddress
                    : device.getAddresses()
            ) {

                InetAddress address =
                        pcapAddress.getAddress();

                if (isUsableIpv4Address(address)) {
                    return device;
                }
            }
        }

        return null;
    }

    private boolean isUsableIpv4Address(
            InetAddress address) {

        return address instanceof Inet4Address
                && !address.isLoopbackAddress()
                && !address.isLinkLocalAddress()
                && !address.isAnyLocalAddress()
                && !address.isMulticastAddress();
    }

    private Set<String> getLocalAddresses(
            PcapNetworkInterface device) {

        Set<String> localAddresses =
                new HashSet<>();

        for (
            PcapAddress pcapAddress
                : device.getAddresses()
        ) {

            InetAddress address =
                    pcapAddress.getAddress();

            if (address != null) {
                localAddresses.add(
                        address.getHostAddress()
                );
            }
        }

        return localAddresses;
    }

    private boolean isExternalAddress(
            String addressText) {

        try {
            InetAddress address =
                    InetAddress.getByName(
                            addressText
                    );

            if (
                address.isAnyLocalAddress()
                        || address.isLoopbackAddress()
                        || address.isLinkLocalAddress()
                        || address.isSiteLocalAddress()
                        || address.isMulticastAddress()
            ) {
                return false;
            }

            byte[] addressBytes =
                    address.getAddress();

            if (
                address instanceof Inet4Address
                        && addressBytes.length == 4
            ) {
                int first =
                        addressBytes[0] & 0xff;

                int second =
                        addressBytes[1] & 0xff;

                if (
                    first == 100
                            && second >= 64
                            && second <= 127
                ) {
                    return false;
                }
            }

            if (
                address instanceof Inet6Address
                        && addressBytes.length == 16
            ) {
                int first =
                        addressBytes[0] & 0xff;

                if (first == 0xfc
                        || first == 0xfd) {

                    return false;
                }
            }

            return true;

        } catch (Exception e) {

            return false;
        }
    }

    private void configureNpcapLibraries() {

        String systemRoot =
                System.getenv("SystemRoot");

        if (systemRoot == null
                || systemRoot.isBlank()) {

            systemRoot = "C:\\Windows";
        }

        String npcapDirectory =
                systemRoot
                        + "\\System32\\Npcap";

        System.setProperty(
                "jna.library.path",
                npcapDirectory
        );

        System.setProperty(
                "org.pcap4j.core.pcapLibName",
                npcapDirectory
                        + "\\wpcap.dll"
        );

        System.setProperty(
                "org.pcap4j.core.packetLibName",
                npcapDirectory
                        + "\\Packet.dll"
        );

        System.setProperty(
                "org.slf4j.simpleLogger.defaultLogLevel",
                "warn"
        );
    }

    private static class TransportInfo {

        private final String protocol;

        private final String sourceAddress;

        private final String destinationAddress;

        private final int sourcePort;

        private final int destinationPort;

        private TransportInfo(
                String protocol,
                String sourceAddress,
                String destinationAddress,
                int sourcePort,
                int destinationPort) {

            this.protocol = protocol;
            this.sourceAddress = sourceAddress;
            this.destinationAddress =
                    destinationAddress;
            this.sourcePort = sourcePort;
            this.destinationPort =
                    destinationPort;
        }
    }
}
