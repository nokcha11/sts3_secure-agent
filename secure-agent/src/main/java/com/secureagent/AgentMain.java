package com.secureagent;

import java.util.List;

import com.secureagent.client.AgentApiClient;
import com.secureagent.collector.NetworkConnectionCollector;
import com.secureagent.collector.PacketMetadataCollector;
import com.secureagent.collector.PortCollector;
import com.secureagent.collector.SystemInfoCollector;
import com.secureagent.model.NetworkConnectionInfo;
import com.secureagent.model.PacketMetadata;
import com.secureagent.model.PortInfo;
import com.secureagent.model.SystemInfo;

public class AgentMain {

    public static void main(String[] args) {

        System.out.println(
                "===== SecureAgent 실행 ====="
        );

        /*
         * 1. 실제 PC 정보 수집
         */
        SystemInfoCollector systemInfoCollector =
                new SystemInfoCollector();

        SystemInfo systemInfo =
                systemInfoCollector.collect();

        System.out.println(
                "PC 이름: "
                        + systemInfo.getComputerName()
        );

        System.out.println(
                "운영체제: "
                        + systemInfo.getOsName()
        );

        System.out.println(
                "운영체제 버전: "
                        + systemInfo.getOsVersion()
        );

        System.out.println(
                "사용자 이름: "
                        + systemInfo.getUserName()
        );

        /*
         * 2. 실제 열린 포트 정보 수집
         */
        PortCollector portCollector =
                new PortCollector();

        List<PortInfo> portList =
                portCollector.collect();

        System.out.println(
                "수집된 열린 포트 항목 수: "
                        + portList.size()
        );

        /*
         * 3. 서버 API 통신 객체 생성
         */
        AgentApiClient apiClient =
                new AgentApiClient();

        /*
         * 4. PC 정보 전송
         */
        boolean systemInfoSuccess =
                apiClient.sendSystemInfo(
                        systemInfo
                );

        if (systemInfoSuccess) {
            System.out.println(
                    "PC 정보를 서버로 정상 전송했습니다."
            );
        } else {
            System.err.println(
                    "PC 정보를 서버로 전송하지 못했습니다."
            );
        }

        /*
         * 5. 실제 열린 포트 목록 전송
         */
        boolean openPortsSuccess =
                apiClient.sendOpenPorts(
                        systemInfo.getComputerName(),
                        portList
                );

        if (openPortsSuccess) {
            System.out.println(
                    "열린 포트 정보를 서버로 정상 전송했습니다."
            );
        } else {
            System.err.println(
                    "열린 포트 정보를 서버로 전송하지 못했습니다."
            );
        }

        /*
         * 6. 실제 Windows 네트워크 연결
         * 수집 및 전송
         */
        try {
            NetworkConnectionCollector
                    networkConnectionCollector =
                            new NetworkConnectionCollector();

            List<NetworkConnectionInfo>
                    networkConnectionList =
                            networkConnectionCollector
                                    .collect();

            System.out.println(
                    "수집된 실제 네트워크 연결 수: "
                            + networkConnectionList.size()
            );

            boolean networkConnectionSuccess =
                    apiClient.sendNetworkConnections(
                            systemInfo.getComputerName(),
                            networkConnectionList
                    );

            if (networkConnectionSuccess) {
                System.out.println(
                        "네트워크 연결 정보를 서버로 "
                                + "정상 전송했습니다."
                );
            } else {
                System.err.println(
                        "네트워크 연결 정보를 서버로 "
                                + "전송하지 못했습니다."
                );
            }

        } catch (RuntimeException e) {
            System.err.println(
                    "네트워크 연결 수집 중 오류가 발생했습니다: "
                            + e.getMessage()
            );

            e.printStackTrace();
        }

        /*
         * 7. 실제 패킷 메타데이터 수집 및 전송
         *
         * Npcap으로 실제 패킷을 수집한 뒤,
         * 같은 통신끼리 메타데이터로 집계하여
         * STS4 서버로 전송합니다.
         *
         * 패킷 원문, 비밀번호, 쿠키,
         * 인증 토큰과 HTTP 본문은
         * 출력하거나 전송하지 않습니다.
         */
        try {
            System.out.println();
            System.out.println(
                    "===== 패킷 메타데이터 수집 및 전송 ====="
            );

            PacketMetadataCollector
                    packetMetadataCollector =
                            new PacketMetadataCollector();

            List<PacketMetadata> packetMetadataList =
                    packetMetadataCollector.collect();

            if (packetMetadataList == null
                    || packetMetadataList.isEmpty()) {

                System.out.println(
                        "수집된 패킷 메타데이터가 없습니다."
                );

                System.out.println(
                        "크롬에서 웹사이트를 연 뒤 "
                                + "다시 실행해 보세요."
                );

            } else {
                System.out.println(
                        "수집된 패킷 메타데이터 묶음 수: "
                                + packetMetadataList.size()
                );

                /*
                 * 콘솔이 너무 길어지지 않도록
                 * 최대 10개만 표시합니다.
                 */
                int displayCount =
                        Math.min(
                                packetMetadataList.size(),
                                10
                        );

                System.out.println(
                        "상위 패킷 메타데이터 "
                                + displayCount
                                + "개를 표시합니다."
                );

                for (int index = 0;
                        index < displayCount;
                        index++) {

                    System.out.println();
                    System.out.println(
                            "[패킷 메타데이터 "
                                    + (index + 1)
                                    + "]"
                    );

                    System.out.println(
                            packetMetadataList.get(index)
                    );
                }

                if (packetMetadataList.size()
                        > displayCount) {

                    System.out.println();
                    System.out.println(
                            "나머지 "
                                    + (
                                        packetMetadataList.size()
                                        - displayCount
                                    )
                                    + "개는 콘솔에서 생략했습니다."
                    );
                }

                /*
                 * 수집된 패킷 메타데이터를
                 * STS4 서버로 전송합니다.
                 */
                System.out.println();

                boolean packetMetadataSuccess =
                        apiClient.sendPacketMetadata(
                                systemInfo.getComputerName(),
                                packetMetadataList
                        );

                if (packetMetadataSuccess) {
                    System.out.println(
                            "패킷 메타데이터를 서버로 "
                                    + "정상 전송했습니다."
                    );
                } else {
                    System.err.println(
                            "패킷 메타데이터를 서버로 "
                                    + "전송하지 못했습니다."
                    );
                }
            }

            System.out.println(
                    "패킷 원문과 민감정보는 "
                            + "저장하지 않았습니다."
            );

            System.out.println(
                    "===== 패킷 메타데이터 수집 및 전송 종료 ====="
            );

        } catch (Exception e) {

            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }

            System.err.println(
                    "패킷 메타데이터 수집 또는 전송 중 "
                            + "오류가 발생했습니다: "
                            + e.getMessage()
            );

            e.printStackTrace();
        }

        System.out.println();
        System.out.println(
                "===== SecureAgent 종료 ====="
        );
    }
}