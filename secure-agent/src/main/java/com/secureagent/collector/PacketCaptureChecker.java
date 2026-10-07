package com.secureagent.collector;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PacketListener;
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

public class PacketCaptureChecker {

    private static final int PACKET_COUNT = 10;

    private static final int SNAPSHOT_LENGTH = 65536;

    private static final int READ_TIMEOUT_MILLISECONDS = 10;

    private static final DateTimeFormatter TIME_FORMATTER =
            DateTimeFormatter.ofPattern(
                    "yyyy-MM-dd HH:mm:ss.SSS"
            );

    public static void main(String[] args) {

        /*
         * Npcap DLL의 위치를 Pcap4J에 알려줍니다.
         */
        configureNpcapLibraries();

        System.out.println(
                "===== 실제 패킷 메타데이터 수집 시작 ====="
        );

        PcapHandle handle = null;

        try {
            /*
             * 현재 사용 중인 실제 네트워크 장치를
             * 자동으로 선택합니다.
             */
            PcapNetworkInterface device =
                    findCaptureDevice();

            if (device == null) {
                System.err.println(
                        "수집할 실제 네트워크 장치를 "
                        + "찾지 못했습니다."
                );

                return;
            }

            System.out.println(
                    "선택한 장치: "
                    + device.getDescription()
            );

            System.out.println(
                    "장치 이름: "
                    + device.getName()
            );

            Set<String> localAddresses =
                    getLocalAddresses(device);

            System.out.println(
                    "내 IP 주소: "
                    + String.join(
                            ", ",
                            localAddresses
                    )
            );

            /*
             * NONPROMISCUOUS:
             * 다른 PC의 모든 통신이 아니라
             * 현재 PC와 관련된 통신만 수집합니다.
             */
            handle = device.openLive(
                    SNAPSHOT_LENGTH,
                    PromiscuousMode.NONPROMISCUOUS,
                    READ_TIMEOUT_MILLISECONDS
            );

            /*
             * TCP와 UDP 패킷만 수집합니다.
             */
            handle.setFilter(
                    "tcp or udp",
                    BpfCompileMode.OPTIMIZE
            );

            AtomicInteger packetNumber =
                    new AtomicInteger(0);

            PacketListener listener = packet -> {

                int number =
                        packetNumber.incrementAndGet();

                printPacketMetadata(
                        number,
                        packet,
                        localAddresses
                );
            };

            System.out.println();
            System.out.println(
                    "TCP/UDP 패킷 "
                    + PACKET_COUNT
                    + "개를 기다리는 중입니다."
            );

            System.out.println(
                    "패킷이 잡히지 않으면 "
                    + "크롬에서 웹사이트를 열어보세요."
            );

            System.out.println();

            handle.loop(
                    PACKET_COUNT,
                    listener
            );

            System.out.println(
                    "패킷 "
                    + PACKET_COUNT
                    + "개 수집을 완료했습니다."
            );

        } catch (PcapNativeException e) {

            System.err.println(
                    "Npcap 패킷 수집 중 오류가 발생했습니다."
            );

            System.err.println(
                    "오류 내용: " + e.getMessage()
            );

            e.printStackTrace();

        } catch (NotOpenException e) {

            System.err.println(
                    "캡처 장치가 열려 있지 않습니다."
            );

            System.err.println(
                    "오류 내용: " + e.getMessage()
            );

        } catch (InterruptedException e) {

            Thread.currentThread().interrupt();

            System.err.println(
                    "패킷 수집 작업이 중단되었습니다."
            );

        } finally {

            if (handle != null) {
                handle.close();
            }
        }

        System.out.println(
                "===== 실제 패킷 메타데이터 수집 종료 ====="
        );
    }

    /*
     * Npcap 네이티브 DLL 경로 설정
     */
    private static void configureNpcapLibraries() {

        String systemRoot =
                System.getenv("SystemRoot");

        if (
            systemRoot == null ||
            systemRoot.isBlank()
        ) {
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

        /*
         * Pcap4J 내부 INFO 로그를 줄입니다.
         */
        System.setProperty(
                "org.slf4j.simpleLogger.defaultLogLevel",
                "warn"
        );
    }

    /*
     * 실제 IPv4 주소가 등록된 장치를 선택합니다.
     * WAN Miniport와 Loopback은 제외합니다.
     */
    private static PcapNetworkInterface
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
                        : device.getName();

            String description =
                    device.getDescription() == null
                        ? ""
                        : device.getDescription();

            if (
                deviceName
                    .toLowerCase()
                    .contains("loopback") ||
                description
                    .toLowerCase()
                    .contains("miniport")
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

    /*
     * 실제 통신에 사용할 수 있는 IPv4인지 확인합니다.
     */
    private static boolean isUsableIpv4Address(
            InetAddress address) {

        return address instanceof Inet4Address
                && !address.isLoopbackAddress()
                && !address.isLinkLocalAddress()
                && !address.isAnyLocalAddress()
                && !address.isMulticastAddress();
    }

    /*
     * 선택된 장치의 IPv4와 IPv6 주소를 가져옵니다.
     */
    private static Set<String> getLocalAddresses(
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

    /*
     * 패킷에서 필요한 메타데이터만 출력합니다.
     * 패킷 원문과 통신 내용은 출력하지 않습니다.
     */
    private static void printPacketMetadata(
            int packetNumber,
            Packet packet,
            Set<String> localAddresses) {

        String sourceAddress = "-";
        String destinationAddress = "-";

        IpV4Packet ipV4Packet =
                packet.get(IpV4Packet.class);

        IpV6Packet ipV6Packet =
                packet.get(IpV6Packet.class);

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
            return;
        }

        String protocol = "알 수 없음";
        String sourcePort = "-";
        String destinationPort = "-";

        TcpPacket tcpPacket =
                packet.get(TcpPacket.class);

        UdpPacket udpPacket =
                packet.get(UdpPacket.class);

        if (tcpPacket != null) {

            protocol = "TCP";

            sourcePort = String.valueOf(
                    tcpPacket
                        .getHeader()
                        .getSrcPort()
                        .valueAsInt()
            );

            destinationPort = String.valueOf(
                    tcpPacket
                        .getHeader()
                        .getDstPort()
                        .valueAsInt()
            );

        } else if (udpPacket != null) {

            protocol = "UDP";

            sourcePort = String.valueOf(
                    udpPacket
                        .getHeader()
                        .getSrcPort()
                        .valueAsInt()
            );

            destinationPort = String.valueOf(
                    udpPacket
                        .getHeader()
                        .getDstPort()
                        .valueAsInt()
            );
        }

        String direction;

        if (localAddresses.contains(sourceAddress)) {
            direction = "송신";
        } else if (
            localAddresses.contains(
                    destinationAddress
            )
        ) {
            direction = "수신";
        } else {
            direction = "기타";
        }

        String capturedAt =
                LocalDateTime.now()
                    .format(TIME_FORMATTER);

        System.out.println(
                "[" + packetNumber + "]"
        );

        System.out.println(
                "수집 시각: " + capturedAt
        );

        System.out.println(
                "방향: " + direction
        );

        System.out.println(
                "프로토콜: " + protocol
        );

        System.out.println(
                "출발지: "
                + sourceAddress
                + ":"
                + sourcePort
        );

        System.out.println(
                "목적지: "
                + destinationAddress
                + ":"
                + destinationPort
        );

        System.out.println(
                "패킷 크기: "
                + packet.length()
                + "바이트"
        );

        System.out.println(
                "--------------------------------"
        );
    }
}