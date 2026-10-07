package com.secureagent.collector;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.secureagent.model.PortInfo;

public class PortCollector {

    public List<PortInfo> collect() {
        List<PortInfo> portList = new ArrayList<>();

        // PID별 실제 프로세스 이름을 먼저 수집합니다.
        Map<Long, String> processNames = collectProcessNames();

        ProcessBuilder processBuilder =
                new ProcessBuilder("netstat", "-ano");

        processBuilder.redirectErrorStream(true);

        try {
            Process process = processBuilder.start();

            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(
                            process.getInputStream(),
                            Charset.defaultCharset()))) {

                String line;

                while ((line = reader.readLine()) != null) {
                    parseLine(line, portList, processNames);
                }
            }

            int exitCode = process.waitFor();

            if (exitCode != 0) {
                throw new IllegalStateException(
                        "netstat 실행 실패: 종료 코드 " + exitCode);
            }

        } catch (IOException e) {
            throw new IllegalStateException(
                    "포트 정보를 수집할 수 없습니다.", e);

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();

            throw new IllegalStateException(
                    "포트 정보 수집이 중단되었습니다.", e);
        }

        portList.sort(
                Comparator.comparing(PortInfo::getProtocol)
                        .thenComparingInt(PortInfo::getLocalPort)
                        .thenComparing(PortInfo::getLocalAddress)
        );

        return portList;
    }

    private Map<Long, String> collectProcessNames() {
        Map<Long, String> processNames = new HashMap<>();

        ProcessBuilder processBuilder =
                new ProcessBuilder("tasklist", "/FO", "CSV", "/NH");

        processBuilder.redirectErrorStream(true);

        try {
            Process process = processBuilder.start();

            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(
                            process.getInputStream(),
                            Charset.defaultCharset()))) {

                String line;

                while ((line = reader.readLine()) != null) {
                    parseTaskListLine(line, processNames);
                }
            }

            int exitCode = process.waitFor();

            if (exitCode != 0) {
                throw new IllegalStateException(
                        "tasklist 실행 실패: 종료 코드 " + exitCode);
            }

        } catch (IOException e) {
            throw new IllegalStateException(
                    "프로세스 이름을 수집할 수 없습니다.", e);

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();

            throw new IllegalStateException(
                    "프로세스 이름 수집이 중단되었습니다.", e);
        }

        return processNames;
    }

    private void parseTaskListLine(
            String line,
            Map<Long, String> processNames) {

        String trimmedLine = line.trim();

        if (!trimmedLine.startsWith("\"")
                || !trimmedLine.endsWith("\"")) {
            return;
        }

        String csvContent = trimmedLine.substring(
                1, trimmedLine.length() - 1);

        String[] columns = csvContent.split("\",\"");

        if (columns.length < 2) {
            return;
        }

        String processName = columns[0];
        String pidText = columns[1];

        try {
            long pid = Long.parseLong(pidText);
            processNames.put(pid, processName);

        } catch (NumberFormatException e) {
            // PID가 숫자가 아니면 무시합니다.
        }
    }

    private void parseLine(
            String line,
            List<PortInfo> portList,
            Map<Long, String> processNames) {

        String trimmedLine = line.trim();

        if (trimmedLine.isEmpty()) {
            return;
        }

        String[] parts = trimmedLine.split("\\s+");

        if (parts.length == 0) {
            return;
        }

        String protocol = parts[0].toUpperCase();

        if ("TCP".equals(protocol)) {
            parseTcp(parts, portList, processNames);

        } else if ("UDP".equals(protocol)) {
            parseUdp(parts, portList, processNames);
        }
    }

    private void parseTcp(
            String[] parts,
            List<PortInfo> portList,
            Map<Long, String> processNames) {

        if (parts.length < 5) {
            return;
        }

        String state = parts[3];

        if (!"LISTENING".equalsIgnoreCase(state)) {
            return;
        }

        addPortInfo(
                "TCP",
                parts[1],
                state.toUpperCase(),
                parts[4],
                portList,
                processNames
        );
    }

    private void parseUdp(
            String[] parts,
            List<PortInfo> portList,
            Map<Long, String> processNames) {

        if (parts.length < 4) {
            return;
        }

        addPortInfo(
                "UDP",
                parts[1],
                "OPEN",
                parts[3],
                portList,
                processNames
        );
    }

    private void addPortInfo(
            String protocol,
            String localEndpoint,
            String state,
            String pidText,
            List<PortInfo> portList,
            Map<Long, String> processNames) {

        int separatorIndex = localEndpoint.lastIndexOf(':');

        if (separatorIndex < 0) {
            return;
        }

        String localAddress =
                localEndpoint.substring(0, separatorIndex);

        String portText =
                localEndpoint.substring(separatorIndex + 1);

        if (localAddress.startsWith("[")
                && localAddress.endsWith("]")) {

            localAddress = localAddress.substring(
                    1, localAddress.length() - 1);
        }

        try {
            int localPort = Integer.parseInt(portText);
            long pid = Long.parseLong(pidText);

            String processName =
                    processNames.getOrDefault(pid, "UNKNOWN");

            PortInfo portInfo = new PortInfo(
                    protocol,
                    localAddress,
                    localPort,
                    state,
                    pid,
                    processName
            );

            portList.add(portInfo);

        } catch (NumberFormatException e) {
            // 포트 번호 또는 PID가 숫자가 아니면 무시합니다.
        }
    }

    public static void main(String[] args) {
        PortCollector collector = new PortCollector();
        List<PortInfo> portList = collector.collect();

        long uniquePortCount = portList.stream()
                .map(portInfo ->
                        portInfo.getProtocol() + ":"
                        + portInfo.getLocalPort() + ":"
                        + portInfo.getPid())
                .distinct()
                .count();

        System.out.println(
                "수집된 원본 항목 수: " + portList.size());

        System.out.println(
                "중복을 합친 열린 포트 수: " + uniquePortCount);

        System.out.println("\n열린 포트 목록 (최대 10개):");

        portList.stream()
                .limit(10)
                .forEach(System.out::println);
    }
}