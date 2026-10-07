package com.secureagent.collector;

import java.nio.charset.StandardCharsets;
import java.util.Locale;

import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;

public class TlsSniExtractor {

    private static final int IP_PROTOCOL_TCP = 6;

    private static final int ETHER_TYPE_IPV4 = 0x0800;

    private static final int ETHER_TYPE_IPV6 = 0x86dd;

    private static final int ETHER_TYPE_VLAN = 0x8100;

    private static final int ETHER_TYPE_PROVIDER_VLAN =
            0x88a8;

    private static final int TLS_CONTENT_TYPE_HANDSHAKE =
            22;

    private static final int TLS_HANDSHAKE_CLIENT_HELLO =
            1;

    private static final int TLS_EXTENSION_SERVER_NAME =
            0;

    /*
     * Pcap4J의 TCP Payload에서 먼저 SNI를 찾고,
     * 찾지 못하면 원시 패킷을 보조적으로 해석합니다.
     */
    public String extract(Packet packet) {

        if (packet == null) {
            return null;
        }

        String serverName =
                extractFromPcapTcp(packet);

        if (serverName != null) {
            return serverName;
        }

        return extractFromRawPacket(packet);
    }

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

        if (!isHttpsPort(sourcePort)
                && !isHttpsPort(destinationPort)) {

            return null;
        }

        Packet payload =
                tcpPacket.getPayload();

        if (payload == null) {
            return null;
        }

        byte[] payloadData =
                payload.getRawData();

        return extractSniFromTlsPayload(
                payloadData,
                0,
                payloadData == null
                        ? 0
                        : payloadData.length
        );
    }

    /*
     * Pcap4J가 TCP Payload까지 변환하지 못한 경우에
     * Ethernet, IP, TCP 헤더를 직접 확인합니다.
     *
     * 원시 데이터는 메모리에서만 잠시 확인하며
     * 파일이나 DB에 저장하지 않습니다.
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

        if (!isHttpsPort(sourcePort)
                && !isHttpsPort(destinationPort)) {

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

        return extractSniFromTlsPayload(
                rawData,
                payloadOffset,
                rawData.length - payloadOffset
        );
    }

    /*
     * TLS Record 안의 ClientHello를 찾습니다.
     */
    private String extractSniFromTlsPayload(
            byte[] data,
            int offset,
            int length) {

        if (!hasRange(
                data,
                offset,
                length
        )) {
            return null;
        }

        int position = offset;
        int end = offset + length;

        while (position + 5 <= end) {

            int contentType =
                    data[position] & 0xff;

            int recordLength =
                    readUnsignedShort(
                            data,
                            position + 3
                    );

            if (recordLength < 0) {
                return null;
            }

            int recordBodyOffset =
                    position + 5;

            int recordEnd =
                    recordBodyOffset
                            + recordLength;

            if (recordEnd > end) {
                /*
                 * ClientHello가 여러 TCP 패킷으로 나뉜 경우에는
                 * 현재 단일 패킷 분석에서 제외합니다.
                 */
                return null;
            }

            if (contentType
                    == TLS_CONTENT_TYPE_HANDSHAKE) {

                String serverName =
                        extractSniFromHandshake(
                                data,
                                recordBodyOffset,
                                recordLength
                        );

                if (serverName != null) {
                    return serverName;
                }
            }

            position = recordEnd;
        }

        return null;
    }

    private String extractSniFromHandshake(
            byte[] data,
            int offset,
            int length) {

        int position = offset;
        int end = offset + length;

        while (position + 4 <= end) {

            int handshakeType =
                    data[position] & 0xff;

            int handshakeLength =
                    readUnsignedMedium(
                            data,
                            position + 1
                    );

            if (handshakeLength < 0
                    || position + 4
                        + handshakeLength > end) {

                return null;
            }

            if (handshakeType
                    == TLS_HANDSHAKE_CLIENT_HELLO) {

                return extractSniFromClientHello(
                        data,
                        position + 4,
                        handshakeLength
                );
            }

            position += 4 + handshakeLength;
        }

        return null;
    }

    /*
     * ClientHello의 확장 목록에서
     * server_name 확장만 확인합니다.
     */
    private String extractSniFromClientHello(
            byte[] data,
            int offset,
            int length) {

        int end = offset + length;

        /*
         * legacy_version 2바이트 + random 32바이트
         */
        int position = offset + 34;

        if (position + 1 > end) {
            return null;
        }

        int sessionIdLength =
                data[position] & 0xff;

        position += 1 + sessionIdLength;

        if (position + 2 > end) {
            return null;
        }

        int cipherSuitesLength =
                readUnsignedShort(
                        data,
                        position
                );

        position += 2 + cipherSuitesLength;

        if (position + 1 > end) {
            return null;
        }

        int compressionMethodsLength =
                data[position] & 0xff;

        position += 1
                + compressionMethodsLength;

        if (position + 2 > end) {
            return null;
        }

        int extensionsLength =
                readUnsignedShort(
                        data,
                        position
                );

        position += 2;

        int extensionsEnd =
                position + extensionsLength;

        if (extensionsEnd > end) {
            return null;
        }

        while (position + 4 <= extensionsEnd) {

            int extensionType =
                    readUnsignedShort(
                            data,
                            position
                    );

            int extensionLength =
                    readUnsignedShort(
                            data,
                            position + 2
                    );

            int extensionDataOffset =
                    position + 4;

            if (extensionLength < 0
                    || extensionDataOffset
                        + extensionLength
                        > extensionsEnd) {

                return null;
            }

            if (extensionType
                    == TLS_EXTENSION_SERVER_NAME) {

                return extractServerNameExtension(
                        data,
                        extensionDataOffset,
                        extensionLength
                );
            }

            position = extensionDataOffset
                    + extensionLength;
        }

        return null;
    }

    private String extractServerNameExtension(
            byte[] data,
            int offset,
            int length) {

        if (length < 2) {
            return null;
        }

        int listLength =
                readUnsignedShort(
                        data,
                        offset
                );

        int position = offset + 2;

        int listEnd =
                position + listLength;

        int extensionEnd =
                offset + length;

        if (listEnd > extensionEnd) {
            return null;
        }

        while (position + 3 <= listEnd) {

            int nameType =
                    data[position] & 0xff;

            int nameLength =
                    readUnsignedShort(
                            data,
                            position + 1
                    );

            position += 3;

            if (nameLength <= 0
                    || position + nameLength
                        > listEnd) {

                return null;
            }

            /*
             * name_type 0은 일반 DNS 호스트 이름입니다.
             */
            if (nameType == 0) {

                String serverName =
                        new String(
                                data,
                                position,
                                nameLength,
                                StandardCharsets.US_ASCII
                        );

                return normalizeServerName(
                        serverName
                );
            }

            position += nameLength;
        }

        return null;
    }

    private String normalizeServerName(
            String serverName) {

        if (serverName == null
                || serverName.isBlank()) {

            return null;
        }

        String normalized =
                serverName.trim()
                        .toLowerCase(
                                Locale.ROOT
                        );

        while (normalized.endsWith(".")) {

            normalized =
                    normalized.substring(
                            0,
                            normalized.length() - 1
                    );
        }

        if (normalized.isBlank()
                || normalized.length() > 253) {

            return null;
        }

        if (!normalized.matches(
                "[a-z0-9.-]+")) {

            return null;
        }

        return normalized;
    }

    private boolean isHttpsPort(int port) {

        return port == 443
                || port == 8443;
    }

    private int findIpOffset(
            byte[] rawData) {

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

        int headerLength =
                (rawData[ipOffset] & 0x0f)
                        * 4;

        if (headerLength < 20
                || rawData.length
                    < ipOffset + headerLength) {

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

        return ipOffset + headerLength;
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

    private boolean hasRange(
            byte[] data,
            int offset,
            int length) {

        return data != null
                && offset >= 0
                && length > 0
                && offset <= data.length
                && length <= data.length - offset;
    }

    private int readUnsignedShort(
            byte[] data,
            int offset) {

        if (data == null
                || offset < 0
                || data.length < offset + 2) {

            return -1;
        }

        return (
            (data[offset] & 0xff) << 8
        ) | (
            data[offset + 1] & 0xff
        );
    }

    private int readUnsignedMedium(
            byte[] data,
            int offset) {

        if (data == null
                || offset < 0
                || data.length < offset + 3) {

            return -1;
        }

        return (
            (data[offset] & 0xff) << 16
        ) | (
            (data[offset + 1] & 0xff) << 8
        ) | (
            data[offset + 2] & 0xff
        );
    }
}
