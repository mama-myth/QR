import '../payload/parsed_payload.dart';
import 'rule_evidence.dart';

/// Deterministic security analyzer for URL payloads.
class UrlAnalyzer {
  static List<RuleEvidence> analyze(UrlPayload payload) {
    final evidence = <RuleEvidence>[];

    // Rule: Malformed URL
    if (payload.isMalformed) {
      evidence.add(
        RuleEvidence(
          ruleId: 'RULE_URL_MALFORMED',
          severity: RuleSeverity.critical,
          outcome: RuleOutcome.matched,
          reasonMessage:
              'URL is syntactically malformed: ${payload.parseError}',
          redactedDetails: {'isMalformed': true},
        ),
      );
      return evidence;
    }

    final host = payload.host ?? '';

    // Rule 1: IP Host Detection (dotted decimal, octal, hex, or bracketed IPv6)
    if (_isIpHost(host)) {
      evidence.add(
        RuleEvidence(
          ruleId: 'RULE_URL_IP_HOST',
          severity: RuleSeverity.critical,
          outcome: RuleOutcome.matched,
          reasonMessage:
              'URL host is a raw IP literal instead of a registered domain name',
          redactedDetails: {'host': host},
        ),
      );
    } else {
      evidence.add(
        const RuleEvidence(
          ruleId: 'RULE_URL_IP_HOST',
          severity: RuleSeverity.info,
          outcome: RuleOutcome.notMatched,
          reasonMessage: 'Host is not a raw IP address',
        ),
      );
    }

    // Rule 2: UserInfo / Embedded Credentials
    if (payload.hasEmbeddedCredentials) {
      evidence.add(
        RuleEvidence(
          ruleId: 'RULE_URL_USERINFO',
          severity: RuleSeverity.critical,
          outcome: RuleOutcome.matched,
          reasonMessage:
              'URL contains embedded credentials or deceptive userinfo prefix',
          redactedDetails: {'hasUserInfo': true},
        ),
      );
    } else {
      evidence.add(
        const RuleEvidence(
          ruleId: 'RULE_URL_USERINFO',
          severity: RuleSeverity.info,
          outcome: RuleOutcome.notMatched,
          reasonMessage: 'No embedded userinfo detected',
        ),
      );
    }

    // Rule 3: Punycode / IDN / Unicode Confusables
    if (payload.hasUnicodeConfusables ||
        host.toLowerCase().startsWith('xn--')) {
      evidence.add(
        RuleEvidence(
          ruleId: 'RULE_URL_CONFUSABLE',
          severity: RuleSeverity.warning,
          outcome: RuleOutcome.matched,
          reasonMessage:
              'URL host uses Internationalized Domain Name (Punycode) or non-ASCII characters that may mimic legitimate domains',
          redactedDetails: {'host': host},
        ),
      );
    } else {
      evidence.add(
        const RuleEvidence(
          ruleId: 'RULE_URL_CONFUSABLE',
          severity: RuleSeverity.info,
          outcome: RuleOutcome.notMatched,
          reasonMessage: 'Host consists strictly of standard ASCII characters',
        ),
      );
    }

    // Rule 4: Duplicate Query Parameters
    if (payload.duplicateParameters.isNotEmpty) {
      evidence.add(
        RuleEvidence(
          ruleId: 'RULE_URL_DUPLICATE_PARAMS',
          severity: RuleSeverity.warning,
          outcome: RuleOutcome.matched,
          reasonMessage:
              'URL contains duplicate query parameters which can cause HTTP parameter pollution',
          redactedDetails: {'duplicateParams': payload.duplicateParameters},
        ),
      );
    }

    // Rule 5: Deceptive Host / Excess Subdomains
    final parts = host.split('.');
    if (parts.length > 4) {
      evidence.add(
        RuleEvidence(
          ruleId: 'RULE_URL_DECEPTIVE_SUBDOMAINS',
          severity: RuleSeverity.warning,
          outcome: RuleOutcome.matched,
          reasonMessage:
              'Excessive subdomain depth (${parts.length} levels) indicative of deceptive structure',
          redactedDetails: {'subdomainCount': parts.length},
        ),
      );
    }

    return evidence;
  }

  static bool _isIpHost(String host) {
    if (host.isEmpty) return false;
    // IPv4 standard dotted
    final ipv4Regex = RegExp(r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$');
    if (ipv4Regex.hasMatch(host)) return true;

    // IPv6 bracketed or raw hex
    if (host.startsWith('[') && host.endsWith(']')) return true;
    if (host.contains(':')) return true;

    // Hex representation e.g. 0x7f000001 or octal 0177.0.0.1
    if (host.startsWith('0x') || RegExp(r'^0[0-7]+').hasMatch(host)) {
      return true;
    }

    // Pure integer IP representation e.g. 2130706433
    if (RegExp(r'^\d+$').hasMatch(host)) {
      return true;
    }

    return false;
  }
}

/// Deterministic security analyzer for UPI payloads (`upi://pay`).
class UpiAnalyzer {
  static List<RuleEvidence> analyze(UpiPayload payload) {
    final evidence = <RuleEvidence>[];

    // Rule 1: Malformed UPI (missing required pa)
    if (payload.isMalformed ||
        payload.payeeVpa == null ||
        payload.payeeVpa!.isEmpty) {
      evidence.add(
        RuleEvidence(
          ruleId: 'RULE_UPI_MALFORMED',
          severity: RuleSeverity.critical,
          outcome: RuleOutcome.matched,
          reasonMessage: 'UPI payload is missing mandatory payee VPA (pa)',
          redactedDetails: {'isMalformed': true},
        ),
      );
      return evidence;
    }

    final vpa = payload.payeeVpa!;

    // Rule 2: VPA Format Validation (must be handle@provider)
    final vpaRegex = RegExp(r'^[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}$');
    if (!vpaRegex.hasMatch(vpa)) {
      evidence.add(
        RuleEvidence(
          ruleId: 'RULE_UPI_INVALID_VPA_FORMAT',
          severity: RuleSeverity.warning,
          outcome: RuleOutcome.matched,
          reasonMessage:
              'UPI payee VPA does not match standard identifier format',
          redactedDetails: {'formatMatched': false},
        ),
      );
    } else {
      evidence.add(
        const RuleEvidence(
          ruleId: 'RULE_UPI_INVALID_VPA_FORMAT',
          severity: RuleSeverity.info,
          outcome: RuleOutcome.notMatched,
          reasonMessage: 'UPI payee VPA matches standard format',
        ),
      );
    }

    // Rule 3: Amount Validation
    if (payload.amount != null) {
      final parsedAmount = double.tryParse(payload.amount!);
      if (parsedAmount == null || parsedAmount <= 0) {
        evidence.add(
          RuleEvidence(
            ruleId: 'RULE_UPI_INVALID_AMOUNT',
            severity: RuleSeverity.warning,
            outcome: RuleOutcome.matched,
            reasonMessage: 'UPI amount is non-numeric, zero, or negative',
            redactedDetails: {'rawAmount': payload.amount},
          ),
        );
      } else {
        evidence.add(
          RuleEvidence(
            ruleId: 'RULE_UPI_INVALID_AMOUNT',
            severity: RuleSeverity.info,
            outcome: RuleOutcome.notMatched,
            reasonMessage: 'UPI amount is valid positive decimal',
            redactedDetails: {'amount': parsedAmount.toStringAsFixed(2)},
          ),
        );
      }
    }

    // Rule 4: Duplicate Parameters
    if (payload.duplicateParameters.isNotEmpty) {
      evidence.add(
        RuleEvidence(
          ruleId: 'RULE_UPI_DUPLICATE_PARAMS',
          severity: RuleSeverity.warning,
          outcome: RuleOutcome.matched,
          reasonMessage: 'Duplicate parameters present in UPI query string',
          redactedDetails: {'duplicateParams': payload.duplicateParameters},
        ),
      );
    }

    return evidence;
  }
}

/// Deterministic security analyzer for Wi-Fi payloads.
class WifiAnalyzer {
  static List<RuleEvidence> analyze(WifiPayload payload) {
    final evidence = <RuleEvidence>[];

    if (payload.isMalformed || payload.ssid == null || payload.ssid!.isEmpty) {
      evidence.add(
        RuleEvidence(
          ruleId: 'RULE_WIFI_MALFORMED',
          severity: RuleSeverity.critical,
          outcome: RuleOutcome.matched,
          reasonMessage: 'Wi-Fi configuration missing mandatory SSID',
          redactedDetails: {'isMalformed': true},
        ),
      );
      return evidence;
    }

    // Rule 1: Open / Unencrypted Wi-Fi Network
    final auth = payload.authType.toUpperCase();
    if (auth == 'NOPASS' || auth.isEmpty) {
      evidence.add(
        const RuleEvidence(
          ruleId: 'RULE_WIFI_UNENCRYPTED',
          severity: RuleSeverity.warning,
          outcome: RuleOutcome.matched,
          reasonMessage:
              'Wi-Fi network is unencrypted (open/no password); communications may be intercepted',
          redactedDetails: {'authType': 'OPEN'},
        ),
      );
    } else {
      evidence.add(
        RuleEvidence(
          ruleId: 'RULE_WIFI_UNENCRYPTED',
          severity: RuleSeverity.info,
          outcome: RuleOutcome.notMatched,
          reasonMessage: 'Wi-Fi network requires authentication ($auth)',
        ),
      );
    }

    return evidence;
  }
}

/// Deterministic security analyzer for Phone payloads.
class PhoneAnalyzer {
  static List<RuleEvidence> analyze(PhonePayload payload) {
    final evidence = <RuleEvidence>[];

    if (payload.isMalformed || payload.sanitizedNumber.isEmpty) {
      evidence.add(
        RuleEvidence(
          ruleId: 'RULE_PHONE_MALFORMED',
          severity: RuleSeverity.warning,
          outcome: RuleOutcome.matched,
          reasonMessage: 'Phone payload contains empty or invalid dial string',
          redactedDetails: {'isMalformed': true},
        ),
      );
      return evidence;
    }

    if (payload.containsControlChars) {
      evidence.add(
        const RuleEvidence(
          ruleId: 'RULE_PHONE_CONTROL_CHARS',
          severity: RuleSeverity.critical,
          outcome: RuleOutcome.matched,
          reasonMessage: 'Telephone URI contains unexpected control characters',
        ),
      );
    }

    // Rule: Premium Rate / Special Service Prefix check
    final num = payload.sanitizedNumber;
    if (num.startsWith('900') ||
        num.startsWith('1900') ||
        num.startsWith('+1900')) {
      evidence.add(
        const RuleEvidence(
          ruleId: 'RULE_PHONE_PREMIUM_RATE',
          severity: RuleSeverity.warning,
          outcome: RuleOutcome.matched,
          reasonMessage: 'Phone number matches premium-rate toll prefix',
        ),
      );
    }

    return evidence;
  }
}

/// Deterministic analyzer for Text & Prompt Injection attempts.
class TextAnalyzer {
  static List<RuleEvidence> analyze(TextPayload payload) {
    final evidence = <RuleEvidence>[];

    if (payload.containsControlChars) {
      evidence.add(
        const RuleEvidence(
          ruleId: 'RULE_TEXT_CONTROL_CHARS',
          severity: RuleSeverity.warning,
          outcome: RuleOutcome.matched,
          reasonMessage:
              'Text contains non-printable Unicode control characters',
        ),
      );
    }

    // Check for prompt injection keywords
    final lower = payload.rawInput.toLowerCase();
    final injectionPatterns = [
      'ignore all previous instructions',
      'ignore previous instructions',
      'disregard previous instructions',
      'system prompt',
      'you are now',
      'report verified',
      'set status to verified',
    ];

    final matchedPatterns = injectionPatterns
        .where((p) => lower.contains(p))
        .toList();

    if (matchedPatterns.isNotEmpty) {
      evidence.add(
        RuleEvidence(
          ruleId: 'RULE_PROMPT_INJECTION',
          severity: RuleSeverity.warning,
          outcome: RuleOutcome.matched,
          reasonMessage:
              'Payload contains prompt-injection instructions. Untrusted payload has no administrative or policy authority.',
          redactedDetails: {'patternsDetected': matchedPatterns.length},
        ),
      );
    } else {
      evidence.add(
        const RuleEvidence(
          ruleId: 'RULE_PROMPT_INJECTION',
          severity: RuleSeverity.info,
          outcome: RuleOutcome.notMatched,
          reasonMessage: 'No adversarial prompt injection patterns detected',
        ),
      );
    }

    return evidence;
  }
}

/// Unified dispatcher running all applicable deterministic rule analyzers.
class RuleEngine {
  static List<RuleEvidence> evaluate(ParsedPayload payload) {
    switch (payload.type) {
      case PayloadType.url:
        return UrlAnalyzer.analyze(payload as UrlPayload);
      case PayloadType.upi:
        return UpiAnalyzer.analyze(payload as UpiPayload);
      case PayloadType.wifi:
        return WifiAnalyzer.analyze(payload as WifiPayload);
      case PayloadType.phone:
        return PhoneAnalyzer.analyze(payload as PhonePayload);
      case PayloadType.text:
        return TextAnalyzer.analyze(payload as TextPayload);
    }
  }
}
