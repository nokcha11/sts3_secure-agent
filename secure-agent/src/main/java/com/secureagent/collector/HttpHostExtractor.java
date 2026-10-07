package com.secureagent.collector;

import java.nio.charset.StandardCharsets;
import java.util.Locale;

import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;

public class HttpHostExtractor {

    private static final int MAX_HEADER_LENGTH = 8192;

    private static final int IP_PROTOCOL_TCP = 6;

    private static final int ETHER_TYPE_IPV4 = 0x0800;

    private static final int ETHER_TYPE_IPV6 = 0x86dd;

    private static final int ETHER_TYPE_VLAN = 0x8100;

    private static final int ETHER_TYPE_PROVIDER_VLAN =
            0x88a8;

    /*
     * 먼저 Pcap4J가 만든 TCP 객체에서 Host를 찾고,
     * 찾지 못하면 원시 패킷을 보조적으로 해석합니다.
     */
    public String extract(Packet packet) {

        if (packet == null) {
            return null;
        }

        String httpHost =
                extractFromPcapTcp(packet);

        if (httpHost != null) {
            return httpHost;
        }

        return extractFromRawPacket(packet);
    }

    /*
     * Pcap4J가 TCP Payload까지 정상 변환한 경우입니다.
     */
    private String extractFromPcapTcp(
            Packet packet) {

        TcpPacket tcpPacket =
                packet.get(TcpPacket.class);

        if (tcpPacket == null) {
            return null;
        }

        int sourcePort =
                tcpPacket.getHeader()
                        .getSrcPort()
                        .valueAsInt();

        int destinationPort =
                tcpPacket.getHeader()
                        .getDstPort()
                        .valueAsInt();

        if (!isHttpPort(sourcePort)
                && !isHttpPort(destinationPort)) {

            return null;
        }

        Packet payload =
                tcpPacket.getPayload();

        if (payload == null) {
            return null;
        }

        return extractHostFromPayload(
                payload.getRawData()
        );
    }

    /*
     * Pcap4J의 TCP 객체 변환이 실패한 경우에는
     * Ethernet, IP, TCP 헤더 위치를 직접 확인합니다.
     *
     * 원시 패킷은 메모리에서 잠시 확인할 뿐
     * 파일이나 DB에는 저장하지 않습니다.
     */
    private String extractFromRawPacket(
            Packet packet) {

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

        int tcpOffset;

        if (ipVersion == 4) {

            tcpOffset =
                    findIpv4TcpOffset(
                            rawData,
                            ipOffset
                    );

        } else if (ipVersion == 6) {

            tcpOffset =
                    findIpv6TcpOffset(
                            rawData,
                            ipOffset
                    );

        } else {

            return null;
        }

        if (tcpOffset < 0
                || rawData.length
                    < tcpOffset + 20) {

            return null;
        }

        int sourcePort =
                readUnsignedShort(
                        rawData,
                        tcpOffset
                );

        int destinationPort =
                readUnsignedShort(
                        rawData,
                        tcpOffset + 2
                );

        if (!isHttpPort(sourcePort)
                && !isHttpPort(destinationPort)) {

            return null;
        }

        int tcpHeaderLength =
                (
                    (rawData[tcpOffset + 12]
                            >> 4) & 0x0f
                ) * 4;

        if (tcpHeaderLength < 20) {
            return null;
        }

        int payloadOffset =
                tcpOffset + tcpHeaderLength;

        if (payloadOffset >= rawData.length) {
            return null;
        }

        int payloadLength =
                rawData.length - payloadOffset;

        return extractHostFromPayload(
                rawData,
                payloadOffset,
                payloadLength
        );
    }

    private int findIpOffset(
            byte[] rawData) {

        /*
         * Ethernet 프레임인지 먼저 확인합니다.
         */
        if (rawData.length >= 14) {

            int etherType =
                    readUnsignedShort(
                            rawData,
                            12
                    );

            int payloadOffset = 14;

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
        }

        /*
         * Ethernet 헤더 없이 IP 패킷만 전달된 경우입니다.
         */
        int firstVersion =
                (rawData[0] >> 4)
                        & 0x0f;

        if (firstVersion == 4
                || firstVersion == 6) {

            return 0;
        }

        return -1;
    }

    private int findIpv4TcpOffset(
            byte[] rawData,
            int ipOffset) {

        if (rawData.length
                < ipOffset + 20) {

            return -1;
        }

        int ipHeaderLength =
                (rawData[ipOffset] & 0x0f)
                        * 4;

        if (ipHeaderLength < 20
                || rawData.length
                    < ipOffset + ipHeaderLength) {

            return -1;
        }

        int fragmentInfo =
                readUnsignedShort(
                        rawData,
                        ipOffset + 6
                );

        if ((fragmentInfo & 0x1fff) != 0) {
            return -1;
        }

        int protocolNumber =
                rawData[ipOffset + 9]
                        & 0xff;

        if (protocolNumber != IP_PROTOCOL_TCP) {
            return -1;
        }

        return ipOffset + ipHeaderLength;
    }

    private int findIpv6TcpOffset(
            byte[] rawData,
            int ipOffset) {

        if (rawData.length
                < ipOffset + 40) {

            return -1;
        }

        int nextHeader =
                rawData[ipOffset + 6]
                        & 0xff;

        int transportOffset =
                ipOffset + 40;

        for (int count = 0;
                count < 8;
                count++) {

            if (nextHeader == 0
                    || nextHeader == 43
                    || nextHeader == 60) {

                if (rawData.length
                        < transportOffset + 2) {

                    return -1;
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

                    return -1;
                }

                nextHeader = newNextHeader;
                transportOffset += extensionLength;
                continue;
            }

            if (nextHeader == 44) {

                if (rawData.length
                        < transportOffset + 8) {

                    return -1;
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
                    return -1;
                }

                nextHeader =
                        rawData[transportOffset]
                                & 0xff;

                transportOffset += 8;
                continue;
            }

            if (nextHeader == 51) {

                if (rawData.length
                        < transportOffset + 2) {

                    return -1;
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

                    return -1;
                }

                nextHeader = newNextHeader;
                transportOffset += extensionLength;
                continue;
            }

            break;
        }

        if (nextHeader != IP_PROTOCOL_TCP) {
            return -1;
        }

        return transportOffset;
    }

    private String extractHostFromPayload(
            byte[] payloadData) {

        if (payloadData == null) {
            return null;
        }

        return extractHostFromPayload(
                payloadData,
                0,
                payloadData.length
        );
    }

    private String extractHostFromPayload(
            byte[] payloadData,
            int offset,
            int length) {

        if (payloadData == null
                || offset < 0
                || length <= 0
                || payloadData.length
                    < offset + length) {

            return null;
        }

        int readableLength =
                Math.min(
                        length,
                        MAX_HEADER_LENGTH
                );

        String headerText =
                new String(
                        payloadData,
                        offset,
                        readableLength,
                        StandardCharsets.ISO_8859_1
                );

        if (!isHttpRequest(headerText)) {
            return null;
        }

        return findHostHeader(headerText);
    }

    private boolean isHttpPort(int port) {

        return port == 80
                || port == 8080;
    }

    private boolean isHttpRequest(
            String headerText) {

        if (headerText == null
                || headerText.isBlank()) {

            return false;
        }

        String upperText =
                headerText.toUpperCase(
                        Locale.ROOT
                );

        return upperText.startsWith("GET ")
                || upperText.startsWith("POST ")
                || upperText.startsWith("HEAD ")
                || upperText.startsWith("PUT ")
                || upperText.startsWith("DELETE ")
                || upperText.startsWith("OPTIONS ")
                || upperText.startsWith("PATCH ")
                || upperText.startsWith("CONNECT ")
                || upperText.startsWith("TRACE ");
    }

    private String findHostHeader(
            String headerText) {

        String[] headerLines =
                headerText.split("\\r?\\n");

        for (String headerLine : headerLines) {

            int colonIndex =
                    headerLine.indexOf(':');

            if (colonIndex <= 0) {
                continue;
            }

            String headerName =
                    headerLine.substring(
                            0,
                            colonIndex
                    ).trim();

            if (!headerName.equalsIgnoreCase(
                    "Host")) {

                continue;
            }

            String hostValue =
                    headerLine.substring(
                            colonIndex + 1
                    ).trim();

            return normalizeHost(hostValue);
        }

        return null;
    }

    private String normalizeHost(
            String hostValue) {

        if (hostValue == null
                || hostValue.isBlank()) {

            return null;
        }

        String normalizedHost =
                hostValue.trim()
                        .toLowerCase(
                                Locale.ROOT
                        );

        if (normalizedHost.startsWith("[")) {

            int closingBracketIndex =
                    normalizedHost.indexOf(']');

            if (closingBracketIndex > 1) {

                normalizedHost =
                        normalizedHost.substring(
                                1,
                                closingBracketIndex
                        );
            }

        } else {

            int colonIndex =
                    normalizedHost.lastIndexOf(':');

            if (colonIndex > 0
                    && normalizedHost.indexOf(':')
                        == colonIndex) {

                String portText =
                        normalizedHost.substring(
                                colonIndex + 1
                        );

                if (portText.matches("\\d+")) {

                    normalizedHost =
                            normalizedHost.substring(
                                    0,
                                    colonIndex
                            );
                }
            }
        }

        if (normalizedHost.isBlank()
                || normalizedHost.length() > 255) {

            return null;
        }

        if (!normalizedHost.matches(
                "[a-z0-9._:-]+")) {

            return null;
        }

        return normalizedHost;
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
}
