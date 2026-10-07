package com.secureagent.client;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;

import com.google.gson.Gson;
import com.secureagent.model.NetworkConnectionInfo;
import com.secureagent.model.PacketMetadata;
import com.secureagent.model.PortInfo;
import com.secureagent.model.SystemInfo;

/*
 * SecureAgent에서 수집한 정보를
 * STS4 서버로 전송하는 클래스입니다.
 */
public class AgentApiClient {

    private static final String SERVER_BASE_URL =
            System.getenv()
                  .getOrDefault("SECURE_SERVER_BASE_URL", "http://localhost:8081")
                  .replaceAll("/+$", "");

    /*
     * 시스템 정보 전송 주소입니다.
     */
    private static final String SYSTEM_INFO_API_URL =
            SERVER_BASE_URL + "/api/agents/system-info";

    /*
     * 열린 포트 정보 전송 주소입니다.
     */
    private static final String OPEN_PORTS_API_URL =
            SERVER_BASE_URL + "/api/agents/%s/open-ports";

    /*
     * 네트워크 연결 정보 전송 주소입니다.
     */
    private static final String NETWORK_CONNECTIONS_API_URL =
            SERVER_BASE_URL + "/api/agents/%s/network-connections";

    /*
     * 패킷 메타데이터 전송 주소입니다.
     */
    private static final String PACKET_METADATA_API_URL =
            SERVER_BASE_URL + "/api/agents/%s/packet-metadata";

    /*
     * STS3 Run Configurations에 등록한
     * 에이전트 API Key를 가져옵니다.
     *
     * 실제 API Key는 Java 코드에
     * 직접 저장하지 않습니다.
     */
    private static final String AGENT_API_KEY =
            System.getenv(
                    "SECURE_AGENT_API_KEY"
            );

    private final HttpClient httpClient;

    private final Gson gson;

    /*
     * 서버 통신에 사용할 HttpClient와
     * JSON 변환 객체를 생성합니다.
     */
    public AgentApiClient() {

        httpClient =
                HttpClient.newBuilder()
                        .connectTimeout(
                                Duration.ofSeconds(5)
                        )
                        .build();

        gson = new Gson();
    }

    /*
     * 시스템 정보를 서버에 전송합니다.
     */
    public boolean sendSystemInfo(
            SystemInfo systemInfo) {

        return sendPostRequest(
                SYSTEM_INFO_API_URL,
                systemInfo,
                "시스템 정보"
        );
    }

    /*
     * 열린 포트 목록을 서버에 전송합니다.
     */
    public boolean sendOpenPorts(
            String computerName,
            List<PortInfo> portList) {

        if (computerName == null
                || computerName.isBlank()) {

            System.err.println(
                    "컴퓨터 이름이 없습니다."
            );

            return false;
        }

        if (portList == null
                || portList.isEmpty()) {

            System.err.println(
                    "전송할 열린 포트 정보가 없습니다."
            );

            return false;
        }

        String requestUrl =
                String.format(
                        OPEN_PORTS_API_URL,
                        computerName
                );

        System.out.println(
                "열린 포트 "
                        + portList.size()
                        + "개를 전송합니다."
        );

        return sendPostRequest(
                requestUrl,
                portList,
                "열린 포트 정보"
        );
    }

    /*
     * 실제 Windows 네트워크 연결 목록을
     * 서버에 전송합니다.
     */
    public boolean sendNetworkConnections(
            String computerName,
            List<NetworkConnectionInfo>
                    connectionList) {

        if (computerName == null
                || computerName.isBlank()) {

            System.err.println(
                    "컴퓨터 이름이 없습니다."
            );

            return false;
        }

        if (connectionList == null) {

            System.err.println(
                    "네트워크 연결 목록이 null입니다."
            );

            return false;
        }

        String requestUrl =
                String.format(
                        NETWORK_CONNECTIONS_API_URL,
                        computerName
                );

        System.out.println(
                "네트워크 연결 "
                        + connectionList.size()
                        + "개를 전송합니다."
        );

        return sendPostRequest(
                requestUrl,
                connectionList,
                "네트워크 연결 정보"
        );
    }

    /*
     * 패킷 메타데이터 목록을
     * STS4 서버에 전송합니다.
     */
    public boolean sendPacketMetadata(
            String computerName,
            List<PacketMetadata>
                    packetMetadataList) {

        if (computerName == null
                || computerName.isBlank()) {

            System.err.println(
                    "컴퓨터 이름이 없습니다."
            );

            return false;
        }

        if (packetMetadataList == null
                || packetMetadataList.isEmpty()) {

            System.err.println(
                    "전송할 패킷 메타데이터가 없습니다."
            );

            return false;
        }

        String requestUrl =
                String.format(
                        PACKET_METADATA_API_URL,
                        computerName
                );

        System.out.println(
                "패킷 메타데이터 "
                        + packetMetadataList.size()
                        + "개를 전송합니다."
        );

        return sendPostRequest(
                requestUrl,
                packetMetadataList,
                "패킷 메타데이터"
        );
    }

    /*
     * 시스템 정보, 열린 포트,
     * 네트워크 연결, 패킷 메타데이터가
     * 공통으로 사용하는 POST 전송 메서드입니다.
     */
    private boolean sendPostRequest(
            String requestUrl,
            Object requestData,
            String dataName) {

        /*
         * STS3 환경변수에 API Key가 없으면
         * 보안상 서버 전송을 진행하지 않습니다.
         */
        if (AGENT_API_KEY == null
                || AGENT_API_KEY.isBlank()) {

            System.err.println(
                    "SECURE_AGENT_API_KEY가 "
                    + "설정되지 않았습니다."
            );

            return false;
        }

        /*
         * 수집한 데이터를 JSON으로 변환합니다.
         */
        String json =
                gson.toJson(requestData);

        /*
         * 모든 POST 요청에
         * X-Agent-Api-Key 헤더를 추가합니다.
         */
        HttpRequest request =
                HttpRequest.newBuilder()
                        .uri(
                                URI.create(
                                        requestUrl
                                )
                        )
                        .timeout(
                                Duration.ofSeconds(15)
                        )
                        .header(
                                "Content-Type",
                                "application/json; charset=utf-8"
                        )
                        .header(
                                "X-Agent-Api-Key",
                                AGENT_API_KEY
                        )
                        .POST(
                                HttpRequest.BodyPublishers
                                        .ofString(
                                                json,
                                                StandardCharsets.UTF_8
                                        )
                        )
                        .build();

        try {

            /*
             * 서버에 요청을 보내고
             * 문자열 응답을 받습니다.
             */
            HttpResponse<String> response =
                    httpClient.send(
                            request,
                            HttpResponse.BodyHandlers
                                    .ofString(
                                            StandardCharsets.UTF_8
                                    )
                    );

            int statusCode =
                    response.statusCode();

            System.out.println(
                    dataName
                            + " 서버 응답 코드: "
                            + statusCode
            );

            System.out.println(
                    dataName
                            + " 서버 응답 내용: "
                            + response.body()
            );

            /*
             * HTTP 상태 코드가 200번대이면
             * 정상 전송으로 처리합니다.
             */
            boolean success =
                    statusCode >= 200
                    && statusCode < 300;

            if (success) {

                System.out.println(
                        dataName + " 전송 성공"
                );

            } else {

                System.err.println(
                        dataName + " 전송 실패"
                );
            }

            return success;

        } catch (IOException exception) {

            System.err.println(
                    "서버 연결 또는 전송 실패: "
                            + exception.getMessage()
            );

            return false;

        } catch (InterruptedException exception) {

            Thread.currentThread().interrupt();

            System.err.println(
                    "전송 작업이 중단되었습니다."
            );

            return false;
        }
    }
}