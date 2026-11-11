import 'package:flutter_test/flutter_test.dart';
import 'package:peek_in_qr/core/payload/parsed_payload.dart';
import 'package:peek_in_qr/core/payload/payload_parser.dart';
import 'package:peek_in_qr/core/rules/rule_engine.dart';
import 'package:peek_in_qr/core/rules/rule_evidence.dart';
import 'fixtures/adversarial_fixtures.dart';

void main() {
  group('URL Parsers and Analyzers', () {
    test('parses benign URL and verifies clean rule evidence', () {
      final payload = PayloadParser.parse(AdversarialFixtures.benignUrl);
      expect(payload.type, PayloadType.url);
      expect(payload.isMalformed, isFalse);

      final urlPayload = payload as UrlPayload;
      expect(urlPayload.scheme, 'https');
      expect(urlPayload.host, 'example.com');
      expect(urlPayload.hasEmbeddedCredentials, isFalse);

      final evidence = RuleEngine.evaluate(payload);
      final criticals = evidence.where(
        (e) =>
            e.severity == RuleSeverity.critical &&
            e.outcome == RuleOutcome.matched,
      );
      expect(criticals, isEmpty);
    });

    test('detects IPv4 literal host as critical evidence', () {
      final payload = PayloadParser.parse(AdversarialFixtures.ipHostUrl);
      expect(payload.type, PayloadType.url);

      final evidence = RuleEngine.evaluate(payload);
      final ipMatch = evidence.firstWhere(
        (e) => e.ruleId == 'RULE_URL_IP_HOST',
      );
      expect(ipMatch.outcome, RuleOutcome.matched);
      expect(ipMatch.severity, RuleSeverity.critical);
    });

    test('detects hex IP host representation', () {
      final payload = PayloadParser.parse(AdversarialFixtures.hexIpHostUrl);
      final evidence = RuleEngine.evaluate(payload);
      final ipMatch = evidence.firstWhere(
        (e) => e.ruleId == 'RULE_URL_IP_HOST',
      );
      expect(ipMatch.outcome, RuleOutcome.matched);
    });

    test('detects embedded userinfo credentials as critical evidence', () {
      final payload = PayloadParser.parse(
        AdversarialFixtures.userinfoDeceptiveUrl,
      );
      expect(payload.type, PayloadType.url);

      final evidence = RuleEngine.evaluate(payload);
      final userinfoMatch = evidence.firstWhere(
        (e) => e.ruleId == 'RULE_URL_USERINFO',
      );
      expect(userinfoMatch.outcome, RuleOutcome.matched);
      expect(userinfoMatch.severity, RuleSeverity.critical);
    });

    test('detects IDN Punycode confusables as warning evidence', () {
      final payload = PayloadParser.parse(
        AdversarialFixtures.confusablePunycodeUrl,
      );
      final evidence = RuleEngine.evaluate(payload);
      final confusableMatch = evidence.firstWhere(
        (e) => e.ruleId == 'RULE_URL_CONFUSABLE',
      );
      expect(confusableMatch.outcome, RuleOutcome.matched);
      expect(confusableMatch.severity, RuleSeverity.warning);
    });

    test('detects duplicate query parameters', () {
      final payload = PayloadParser.parse(
        AdversarialFixtures.duplicateParamUrl,
      );
      final evidence = RuleEngine.evaluate(payload);
      final dupMatch = evidence.firstWhere(
        (e) => e.ruleId == 'RULE_URL_DUPLICATE_PARAMS',
      );
      expect(dupMatch.outcome, RuleOutcome.matched);
      expect(dupMatch.severity, RuleSeverity.warning);
    });
  });

  group('UPI Parsers and Analyzers', () {
    test('parses benign UPI payload cleanly', () {
      final payload = PayloadParser.parse(AdversarialFixtures.benignUpi);
      expect(payload.type, PayloadType.upi);
      expect(payload.isMalformed, isFalse);

      final upi = payload as UpiPayload;
      expect(upi.payeeVpa, 'merchant@icici');
      expect(upi.payeeName, 'AcmeStore');
      expect(upi.amount, '250.00');

      final evidence = RuleEngine.evaluate(payload);
      final criticals = evidence.where(
        (e) =>
            e.severity == RuleSeverity.critical &&
            e.outcome == RuleOutcome.matched,
      );
      expect(criticals, isEmpty);
    });

    test('flags missing payee VPA as critical malformed payload', () {
      final payload = PayloadParser.parse(AdversarialFixtures.missingPayeeUpi);
      expect(payload.type, PayloadType.upi);
      expect(payload.isMalformed, isTrue);

      final evidence = RuleEngine.evaluate(payload);
      final malformedMatch = evidence.firstWhere(
        (e) => e.ruleId == 'RULE_UPI_MALFORMED',
      );
      expect(malformedMatch.outcome, RuleOutcome.matched);
      expect(malformedMatch.severity, RuleSeverity.critical);
    });

    test('detects invalid VPA format', () {
      final payload = PayloadParser.parse(AdversarialFixtures.invalidVpaUpi);
      final evidence = RuleEngine.evaluate(payload);
      final vpaMatch = evidence.firstWhere(
        (e) => e.ruleId == 'RULE_UPI_INVALID_VPA_FORMAT',
      );
      expect(vpaMatch.outcome, RuleOutcome.matched);
    });

    test('detects negative or non-numeric monetary amounts', () {
      final negPayload = PayloadParser.parse(
        AdversarialFixtures.negativeAmountUpi,
      );
      final negEvidence = RuleEngine.evaluate(negPayload);
      final negMatch = negEvidence.firstWhere(
        (e) => e.ruleId == 'RULE_UPI_INVALID_AMOUNT',
      );
      expect(negMatch.outcome, RuleOutcome.matched);
      expect(negMatch.severity, RuleSeverity.warning);

      final nonNumPayload = PayloadParser.parse(
        AdversarialFixtures.nonNumericAmountUpi,
      );
      final nonNumEvidence = RuleEngine.evaluate(nonNumPayload);
      final nonNumMatch = nonNumEvidence.firstWhere(
        (e) => e.ruleId == 'RULE_UPI_INVALID_AMOUNT',
      );
      expect(nonNumMatch.outcome, RuleOutcome.matched);
    });

    test('detects duplicate parameters in UPI query', () {
      final payload = PayloadParser.parse(
        AdversarialFixtures.duplicateParamUpi,
      );
      final evidence = RuleEngine.evaluate(payload);
      final dupMatch = evidence.firstWhere(
        (e) => e.ruleId == 'RULE_UPI_DUPLICATE_PARAMS',
      );
      expect(dupMatch.outcome, RuleOutcome.matched);
    });
  });

  group('Wi-Fi Parsers and Analyzers', () {
    test('parses WPA Wi-Fi with escaped delimiters', () {
      final payload = PayloadParser.parse(AdversarialFixtures.escapedWifi);
      expect(payload.type, PayloadType.wifi);

      final wifi = payload as WifiPayload;
      expect(wifi.ssid, 'My;Network:Home');
      expect(wifi.authType, 'WPA');
      expect(wifi.hasPassword, isTrue);
    });

    test('flags unencrypted Wi-Fi as warning', () {
      final payload = PayloadParser.parse(AdversarialFixtures.unencryptedWifi);
      expect(payload.type, PayloadType.wifi);

      final evidence = RuleEngine.evaluate(payload);
      final openMatch = evidence.firstWhere(
        (e) => e.ruleId == 'RULE_WIFI_UNENCRYPTED',
      );
      expect(openMatch.outcome, RuleOutcome.matched);
      expect(openMatch.severity, RuleSeverity.warning);
    });

    test('flags missing SSID in Wi-Fi payload as malformed', () {
      final payload = PayloadParser.parse(AdversarialFixtures.missingSsidWifi);
      expect(payload.isMalformed, isTrue);

      final evidence = RuleEngine.evaluate(payload);
      final malformedMatch = evidence.firstWhere(
        (e) => e.ruleId == 'RULE_WIFI_MALFORMED',
      );
      expect(malformedMatch.outcome, RuleOutcome.matched);
      expect(malformedMatch.severity, RuleSeverity.critical);
    });
  });

  group('Phone Parsers and Analyzers', () {
    test('parses benign tel URI safely', () {
      final payload = PayloadParser.parse(AdversarialFixtures.benignPhone);
      expect(payload.type, PayloadType.phone);

      final phone = payload as PhonePayload;
      expect(phone.sanitizedNumber, '+15551234567');
      expect(phone.isMalformed, isFalse);
    });

    test('flags premium rate numbers', () {
      final payload = PayloadParser.parse(AdversarialFixtures.premiumRatePhone);
      final evidence = RuleEngine.evaluate(payload);
      final rateMatch = evidence.firstWhere(
        (e) => e.ruleId == 'RULE_PHONE_PREMIUM_RATE',
      );
      expect(rateMatch.outcome, RuleOutcome.matched);
    });

    test('flags control characters in phone numbers', () {
      final payload = PayloadParser.parse(AdversarialFixtures.controlCharPhone);
      final evidence = RuleEngine.evaluate(payload);
      final ctrlMatch = evidence.firstWhere(
        (e) => e.ruleId == 'RULE_PHONE_CONTROL_CHARS',
      );
      expect(ctrlMatch.outcome, RuleOutcome.matched);
      expect(ctrlMatch.severity, RuleSeverity.critical);
    });
  });

  group('Text & Prompt Injection Analyzers', () {
    test('treats prompt injection as untrusted data without authority', () {
      final payload = PayloadParser.parse(
        AdversarialFixtures.promptInjectionText,
      );
      expect(payload.type, PayloadType.text);

      final evidence = RuleEngine.evaluate(payload);
      final injectionMatch = evidence.firstWhere(
        (e) => e.ruleId == 'RULE_PROMPT_INJECTION',
      );
      expect(injectionMatch.outcome, RuleOutcome.matched);
      expect(injectionMatch.severity, RuleSeverity.warning);
      expect(
        injectionMatch.reasonMessage.contains(
          'Untrusted payload has no administrative or policy authority',
        ),
        isTrue,
      );
    });

    test('detects control characters in text', () {
      final payload = PayloadParser.parse(AdversarialFixtures.controlCharText);
      final evidence = RuleEngine.evaluate(payload);
      final ctrlMatch = evidence.firstWhere(
        (e) => e.ruleId == 'RULE_TEXT_CONTROL_CHARS',
      );
      expect(ctrlMatch.outcome, RuleOutcome.matched);
    });

    test('bounds oversized payload to prevent resource exhaustion', () {
      final payload = PayloadParser.parse(AdversarialFixtures.oversizedPayload);
      expect(payload.isMalformed, isTrue);
      expect(
        payload.parseError!.contains('exceeds maximum bounded length'),
        isTrue,
      );
    });
  });
}
