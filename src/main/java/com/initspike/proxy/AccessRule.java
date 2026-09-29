package com.initspike.proxy;

import java.util.regex.Pattern;

/**
 * One ACL / rewrite / WAF-style rule held entirely in heap after init.
 */
final class AccessRule {
  final int id;
  final String hostGlob;
  final String pathPrefix;
  final Pattern compiled;
  final RuleAction action;
  final String rewriteTarget;
  final byte[] payload;
  final long fingerprint;

  AccessRule(
      int id,
      String hostGlob,
      String pathPrefix,
      Pattern compiled,
      RuleAction action,
      String rewriteTarget,
      byte[] payload,
      long fingerprint) {
    this.id = id;
    this.hostGlob = hostGlob;
    this.pathPrefix = pathPrefix;
    this.compiled = compiled;
    this.action = action;
    this.rewriteTarget = rewriteTarget;
    this.payload = payload;
    this.fingerprint = fingerprint;
  }

  enum RuleAction {
    ALLOW,
    DENY,
    REWRITE
  }
}
