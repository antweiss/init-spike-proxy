package com.initspike.proxy;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.*;

class RuleEngineTest {

    private static AccessRule rule(int id, String host, String path, AccessRule.RuleAction action) {
        String regex = "^https?://" + Pattern.quote(host) + path + "(/.*)?$";
        Pattern compiled = Pattern.compile(regex, Pattern.CASE_INSENSITIVE);
        return new AccessRule(id, host, path, compiled, action, "", new byte[0], 0L);
    }

    private RuleEngine engine;
    private AccessRule allowRule;
    private AccessRule denyRule;
    private AccessRule rewriteRule;

    @BeforeEach
    void setUp() {
        allowRule  = rule(0, "good.example.com",    "/api/v1", AccessRule.RuleAction.ALLOW);
        denyRule   = rule(1, "blocked.example.com", "/secret", AccessRule.RuleAction.DENY);
        rewriteRule = rule(2, "old.example.com",    "/api",    AccessRule.RuleAction.REWRITE);

        List<AccessRule> rules = List.of(allowRule, denyRule, rewriteRule);
        Map<String, List<Integer>> index = Map.of(
                "good.example.com",    new ArrayList<>(List.of(0)),
                "blocked.example.com", new ArrayList<>(List.of(1)),
                "old.example.com",     new ArrayList<>(List.of(2))
        );
        engine = new RuleEngine(rules, index);
    }

    @Test
    void size_returnsNumberOfRules() {
        assertEquals(3, engine.size());
    }

    @Test
    void indexSize_returnsNumberOfHosts() {
        assertEquals(3, engine.indexSize());
    }

    @Test
    void match_nullUri_returnsDefaultAllow() {
        AccessRule result = engine.match(null);
        assertEquals(AccessRule.RuleAction.ALLOW, result.action);
    }

    @Test
    void match_uriWithNoHost_returnsDefaultAllow() {
        AccessRule result = engine.match(URI.create("/just/a/path"));
        assertEquals(AccessRule.RuleAction.ALLOW, result.action);
    }

    @Test
    void match_knownAllowedHost_returnsAllowRule() {
        AccessRule result = engine.match(URI.create("https://good.example.com/api/v1/users"));
        assertEquals(AccessRule.RuleAction.ALLOW, result.action);
        assertEquals(0, result.id);
    }

    @Test
    void match_knownDeniedHost_returnsDenyRule() {
        AccessRule result = engine.match(URI.create("http://blocked.example.com/secret/data"));
        assertEquals(AccessRule.RuleAction.DENY, result.action);
        assertEquals(1, result.id);
    }

    @Test
    void match_knownRewriteHost_returnsRewriteRule() {
        AccessRule result = engine.match(URI.create("https://old.example.com/api/endpoint"));
        assertEquals(AccessRule.RuleAction.REWRITE, result.action);
        assertEquals(2, result.id);
    }

    @Test
    void match_unknownHost_returnsDefaultAllow() {
        AccessRule result = engine.match(URI.create("https://unknown.example.com/anything"));
        assertEquals(AccessRule.RuleAction.ALLOW, result.action);
        assertEquals(-1, result.id);
    }
}
