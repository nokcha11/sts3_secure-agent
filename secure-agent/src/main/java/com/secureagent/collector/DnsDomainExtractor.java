package com.secureagent.collector;

import java.util.List;
import java.util.Locale;

import org.pcap4j.packet.DnsPacket;
import org.pcap4j.packet.DnsQuestion;
import org.pcap4j.packet.Packet;

public class DnsDomainExtractor {

    /*
     * DNS 도메인의 최대 길이입니다.
     *
     * Oracle의 DNS_DOMAIN 컬럼은
     * varchar2(255)이므로 253자로 제한합니다.
     */
    private static final int MAX_DOMAIN_LENGTH =
            253;

    /*
     * Pcap4J Packet 안에 DNS 패킷이 있으면
     * 첫 번째 질문의 도메인을 추출합니다.
     *
     * DNS 패킷이 아니거나 정상적인 도메인이
     * 없으면 null을 반환합니다.
     */
    public String extract(
            Packet packet) {

        if (packet == null) {
            return null;
        }

        DnsPacket dnsPacket =
                packet.get(DnsPacket.class);

        if (dnsPacket == null) {
            return null;
        }

        List<DnsQuestion> questionList =
                dnsPacket
                    .getHeader()
                    .getQuestions();

        if (questionList == null
                || questionList.isEmpty()) {

            return null;
        }

        for (DnsQuestion question
                : questionList) {

            if (question == null
                    || question.getQName() == null) {

                continue;
            }

            String domain =
                    question
                        .getQName()
                        .getName();

            String normalizedDomain =
                    normalizeDomain(domain);

            if (normalizedDomain != null) {
                return normalizedDomain;
            }
        }

        return null;
    }

    /*
     * 추출한 도메인을 저장 가능한 형태로
     * 정리하고 검증합니다.
     */
    private String normalizeDomain(
            String domain) {

        if (domain == null) {
            return null;
        }

        String normalized =
                domain
                    .trim()
                    .toLowerCase(Locale.ROOT);

        /*
         * 도메인 끝에 점이 있으면 제거합니다.
         *
         * 예:
         * www.example.com.
         *     → www.example.com
         */
        while (normalized.endsWith(".")) {

            normalized =
                    normalized.substring(
                            0,
                            normalized.length() - 1
                    );
        }

        if (normalized.isBlank()) {
            return null;
        }

        if (normalized.length()
                > MAX_DOMAIN_LENGTH) {

            return null;
        }

        /*
         * DNS 도메인으로 사용할 문자만 허용합니다.
         *
         * 영문 소문자, 숫자, 점, 하이픈,
         * DNS 서비스 이름에 사용되는 밑줄만
         * 허용합니다.
         */
        if (!normalized.matches(
                "[a-z0-9._-]+"
        )) {

            return null;
        }

        return normalized;
    }
}