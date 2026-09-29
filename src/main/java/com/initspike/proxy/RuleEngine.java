package com.initspike.proxy;

import java.net.URI;
import java.util.List;
import java.util.Map;

final class RuleEngine {
  private final List<AccessRule> rules;
  private final Map<String, List<Integer>> hostIndex;
  private final AccessRule defaultAllow;

  RuleEngine(List<AccessRule> rules, Map<String, List<Integer>> hostIndex) {
    this.rules = rules;
    this.hostIndex = hostIndex;
    this.defaultAllow =
        new AccessRule(
            -1,
            "*",
            "/",
            java.util.regex.Pattern.compile(".*"),
            AccessRule.RuleAction.ALLOW,
            "",
            new byte[0],
            0L);
  }

  int size() {
    return rules.size();
  }

  int indexSize() {
    return hostIndex.size();
  }

  AccessRule match(URI target) {
    if (target == null || target.getHost() == null) {
      return defaultAllow;
    }
    String host = target.getHost();
    String path = target.getPath() == null ? "/" : target.getPath();
    String url = target.toString();

    List<Integer> bucket = hostIndex.get(host);
    if (bucket != null) {
      for (int id : bucket) {
        AccessRule rule = rules.get(id);
        if (path.startsWith(rule.pathPrefix) || rule.compiled.matcher(url).matches()) {
          return rule;
        }
      }
    }

    // Fallback scan of a bounded slice so request path stays cheap after the init spike.
    int start = Math.floorMod(host.hashCode(), rules.size());
    int limit = Math.min(rules.size(), start + 32);
    for (int i = start; i < limit; i++) {
      AccessRule rule = rules.get(i);
      if (rule.compiled.matcher(url).find()) {
        return rule;
      }
    }
    return defaultAllow;
  }
}
