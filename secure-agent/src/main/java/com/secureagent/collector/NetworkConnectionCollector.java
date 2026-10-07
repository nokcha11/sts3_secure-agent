package com.secureagent.collector;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.secureagent.model.NetworkConnectionInfo;

public class NetworkConnectionCollector {

    /*
     * Windows의 실제 TCP/UDP 연결 정보를 수집합니다.
     */
    public List<NetworkConnectionInfo> collect() {
        List<NetworkConnectionInfo> connections =
                new ArrayList<>();

        Map<Long, String> processNames =
                collectProcessNames();

        ProcessBuilder processBuilder =
                new ProcessBuilder(
                        "cmd.exe",
                        "/c",
                        "netstat -ano"
                );

        processBuilder.redirectErrorStream(true);

        try {
            Process process =
                    processBuilder.start();

            try (BufferedReader reader =
                    new BufferedReader(
                            new InputStreamReader(
                                    process.getInputStream(),
                                    Charset.defaultCharset()
                            )
                    )) {

                String line;

                while ((line = reader.readLine()) != null) {
                    String trimmedLine =
                            line.trim();

                    if (trimmedLine.startsWith("TCP ")) {
                        NetworkConnectionInfo connection =
                                parseTcpConnection(
                                        trimmedLine,
                                        processNames
                                );

                        if (connection != null) {
                            connections.add(connection);
                        }
                    }

                    if (trimmedLine.startsWith("UDP ")) {
                        NetworkConnectionInfo connection =
                                parseUdpConnection(
                                        trimmedLine,
                                        processNames
                                );

                        if (connection != null) {
                            connections.add(connection);
                        }
                    }
                }
            }

            int exitCode =
                    process.waitFor();

            if (exitCode != 0) {
                throw new IllegalStateException(
                        "netstat 실행에 실패했습니다. 종료 코드: "
                                + exitCode
                );
            }

        } catch (IOException e) {
            throw new IllegalStateException(
                    "Windows 네트워크 연결을 수집하지 못했습니다.",
                    e
            );

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();

            throw new IllegalStateException(
                    "네트워크 연결 수집 중 작업이 중단되었습니다.",
                    e
            );
        }

        return connections;
    }

    /*
     * TCP 연결 한 줄을 분석합니다.
     *
     * 예:
     * TCP 192.168.0.10:53000 203.0.113.10:443
     * ESTABLISHED 5000
     */
    private NetworkConnectionInfo parseTcpConnection(
            String line,
            Map<Long, String> processNames) {

        String[] parts =
                line.split("\\s+");

        if (parts.length < 5) {
            return null;
        }

        Endpoint localEndpoint =
                parseEndpoint(parts[1]);

        Endpoint remoteEndpoint =
                parseEndpoint(parts[2]);

        String state =
                parts[3];

        Long pid =
                parseLong(parts[4]);

        NetworkConnectionInfo connection =
                new NetworkConnectionInfo();

        connection.setProtocol("TCP");

        connection.setLocalAddress(
                localEndpoint.address
        );

        connection.setLocalPort(
                localEndpoint.port
        );

        connection.setRemoteAddress(
                remoteEndpoint.address
        );

        connection.setRemotePort(
                remoteEndpoint.port
        );

        connection.setState(state);
        connection.setPid(pid);

        connection.setProcessName(
                findProcessName(
                        pid,
                        processNames
                )
        );

        return connection;
    }

    /*
     * UDP 엔드포인트 한 줄을 분석합니다.
     *
     * UDP는 TCP처럼 ESTABLISHED 상태가 없으므로
     * 상태를 OPEN으로 표시합니다.
     */
    private NetworkConnectionInfo parseUdpConnection(
            String line,
            Map<Long, String> processNames) {

        String[] parts =
                line.split("\\s+");

        if (parts.length < 4) {
            return null;
        }

        Endpoint localEndpoint =
                parseEndpoint(parts[1]);

        Endpoint remoteEndpoint =
                parseEndpoint(parts[2]);

        Long pid =
                parseLong(parts[3]);

        NetworkConnectionInfo connection =
                new NetworkConnectionInfo();

        connection.setProtocol("UDP");

        connection.setLocalAddress(
                localEndpoint.address
        );

        connection.setLocalPort(
                localEndpoint.port
        );

        connection.setRemoteAddress(
                remoteEndpoint.address
        );

        connection.setRemotePort(
                remoteEndpoint.port
        );

        connection.setState("OPEN");
        connection.setPid(pid);

        connection.setProcessName(
                findProcessName(
                        pid,
                        processNames
                )
        );

        return connection;
    }

    /*
     * 주소와 포트를 분리합니다.
     *
     * IPv4: 192.168.0.10:53000
     * IPv6: [::1]:8081
     * 미지정: *:*
     */
    private Endpoint parseEndpoint(
            String endpointText) {

        if (endpointText == null ||
                endpointText.isBlank()) {

            return new Endpoint("", null);
        }

        String value =
                endpointText.trim();

        int separatorIndex =
                value.lastIndexOf(':');

        if (separatorIndex < 0) {
            return new Endpoint(
                    value,
                    null
            );
        }

        String address =
                value.substring(
                        0,
                        separatorIndex
                );

        String portText =
                value.substring(
                        separatorIndex + 1
                );

        if (address.startsWith("[") &&
                address.endsWith("]")) {

            address =
                    address.substring(
                            1,
                            address.length() - 1
                    );
        }

        Integer port =
                parseInteger(portText);

        return new Endpoint(
                address,
                port
        );
    }

    /*
     * PID별 프로세스 이름을 수집합니다.
     */
    private Map<Long, String> collectProcessNames() {
        Map<Long, String> processNames =
                new HashMap<>();

        ProcessBuilder processBuilder =
                new ProcessBuilder(
                        "cmd.exe",
                        "/c",
                        "tasklist /FO CSV /NH"
                );

        processBuilder.redirectErrorStream(true);

        try {
            Process process =
                    processBuilder.start();

            try (BufferedReader reader =
                    new BufferedReader(
                            new InputStreamReader(
                                    process.getInputStream(),
                                    Charset.defaultCharset()
                            )
                    )) {

                String line;

                while ((line = reader.readLine()) != null) {
                    addProcessName(
                            line,
                            processNames
                    );
                }
            }

            process.waitFor();

        } catch (IOException e) {
            System.err.println(
                    "프로세스 목록 수집 실패: "
                            + e.getMessage()
            );

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();

            System.err.println(
                    "프로세스 목록 수집 중단"
            );
        }

        return processNames;
    }

    /*
     * tasklist CSV 한 줄에서 프로세스 이름과 PID를 추출합니다.
     */
    private void addProcessName(
            String line,
            Map<Long, String> processNames) {

        if (line == null) {
            return;
        }

        String value =
                line.trim();

        if (!value.startsWith("\"") ||
                !value.endsWith("\"")) {

            return;
        }

        String content =
                value.substring(
                        1,
                        value.length() - 1
                );

        String[] fields =
                content.split("\",\"");

        if (fields.length < 2) {
            return;
        }

        String processName =
                fields[0];

        Long pid =
                parseLong(
                        fields[1].replace(",", "")
                );

        if (pid != null) {
            processNames.put(
                    pid,
                    processName
            );
        }
    }

    private String findProcessName(
            Long pid,
            Map<Long, String> processNames) {

        if (pid == null) {
            return "알 수 없음";
        }

        return processNames.getOrDefault(
                pid,
                "알 수 없음"
        );
    }

    private Integer parseInteger(String value) {
        if (value == null ||
                value.isBlank() ||
                "*".equals(value)) {

            return null;
        }

        try {
            return Integer.valueOf(value);

        } catch (NumberFormatException e) {
            return null;
        }
    }

    private Long parseLong(String value) {
        if (value == null ||
                value.isBlank()) {

            return null;
        }

        try {
            return Long.valueOf(value);

        } catch (NumberFormatException e) {
            return null;
        }
    }

    /*
     * 주소와 포트를 잠시 함께 보관하는 내부 클래스입니다.
     */
    private static class Endpoint {

        private final String address;

        private final Integer port;

        private Endpoint(
                String address,
                Integer port) {

            this.address = address;
            this.port = port;
        }
    }
}