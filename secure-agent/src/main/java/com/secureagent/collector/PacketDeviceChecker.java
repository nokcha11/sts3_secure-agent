package com.secureagent.collector;

import java.net.InetAddress;
import java.util.List;

import org.pcap4j.core.PcapAddress;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;

public class PacketDeviceChecker {

    public static void main(String[] args) {

        System.out.println(
                "===== Npcap 네트워크 장치 확인 ====="
        );

        try {
            List<PcapNetworkInterface> devices =
                    Pcaps.findAllDevs();

            if (devices == null || devices.isEmpty()) {
                System.out.println(
                        "캡처 가능한 네트워크 장치를 "
                        + "찾지 못했습니다."
                );

                return;
            }

            int deviceNumber = 1;

            for (PcapNetworkInterface device : devices) {

                System.out.println();
                System.out.println(
                        "[" + deviceNumber + "] 네트워크 장치"
                );

                System.out.println(
                        "장치 이름: " + device.getName()
                );

                String description =
                        device.getDescription();

                System.out.println(
                        "장치 설명: "
                        + (
                            description == null
                                ? "설명 없음"
                                : description
                        )
                );

                printIpAddresses(device);

                deviceNumber++;
            }

            System.out.println();
            System.out.println(
                    "캡처 가능한 장치 수: "
                    + devices.size()
            );

            System.out.println(
                    "Pcap4J가 Npcap 장치를 "
                    + "정상적으로 인식했습니다."
            );

        } catch (PcapNativeException e) {

            System.err.println(
                    "Npcap 네트워크 장치 조회에 실패했습니다."
            );

            System.err.println(
                    "오류 내용: " + e.getMessage()
            );

            e.printStackTrace();
        }

        System.out.println(
                "===== 네트워크 장치 확인 종료 ====="
        );
    }

    private static void printIpAddresses(
            PcapNetworkInterface device) {

        List<PcapAddress> addresses =
                device.getAddresses();

        if (addresses == null || addresses.isEmpty()) {
            System.out.println(
                    "IP 주소: 등록된 주소 없음"
            );

            return;
        }

        for (PcapAddress pcapAddress : addresses) {

            InetAddress address =
                    pcapAddress.getAddress();

            if (address != null) {
                System.out.println(
                        "IP 주소: "
                        + address.getHostAddress()
                );
            }
        }
    }
}