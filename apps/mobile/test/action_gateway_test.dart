import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:peek_in_qr/core/execution/action_gateway.dart';
import 'package:peek_in_qr/core/execution/consent_token.dart';
import 'package:peek_in_qr/core/fusion/evaluation_result.dart';
import 'package:peek_in_qr/core/payload/parsed_payload.dart';
import 'package:peek_in_qr/core/payload/qr_payload.dart';
import 'package:peek_in_qr/features/diagnostics/diagnostic_screen.dart';

void main() {
  late SafeActionDispatcher dispatcher;
  late ActionGateway gateway;

  setUp(() {
    dispatcher = SafeActionDispatcher();
    gateway = ActionGateway(dispatcher: dispatcher);
  });

  group('ActionGateway Security Invariants', () {
    test('strictly blocks SUSPICIOUS evaluation without executing intent', () async {
      const evaluation = EvaluationResult(
        state: EvaluationState.suspicious,
        reasonCodes: ['RULE_URL_IP_HOST'],
        userMessages: ['Host is an IP literal.'],
        evidenceList: [],
      );

      final token = gateway.createToken(
        scanId: 'scan-1',
        actionType: DestinationActionType.viewUrl,
        canonicalTarget: 'http://192.168.1.1',
      );

      final res = await gateway.executeAction(evaluation: evaluation, token: token);
      expect(res.success, isFalse);
      expect(res.status, 'BLOCKED');
      expect(dispatcher.dispatchedIntents, isEmpty);
    });

    test('requires two-step user confirmation for UNKNOWN evaluation', () async {
      const evaluation = EvaluationResult(
        state: EvaluationState.unknown,
        reasonCodes: ['NO_POSITIVE_PROOF'],
        userMessages: ['Target is unproven.'],
        evidenceList: [],
      );

      final token = gateway.createToken(
        scanId: 'scan-2',
        actionType: DestinationActionType.viewUrl,
        canonicalTarget: 'https://unregistered-site.com',
      );

      // Attempt 1: without confirmation -> Rejected
      final res1 = await gateway.executeAction(
        evaluation: evaluation,
        token: token,
        userConfirmedUnknown: false,
      );
      expect(res1.success, isFalse);
      expect(res1.status, 'REQUIRES_CONFIRMATION');
      expect(dispatcher.dispatchedIntents, isEmpty);

      // Attempt 2: with confirmation -> Executed
      final res2 = await gateway.executeAction(
        evaluation: evaluation,
        token: token,
        userConfirmedUnknown: true,
      );
      expect(res2.success, isTrue);
      expect(res2.status, 'EXECUTED');
      expect(dispatcher.dispatchedIntents.length, 1);
    });

    test('permits VERIFIED evaluation directly with valid token', () async {
      const evaluation = EvaluationResult(
        state: EvaluationState.verified,
        reasonCodes: ['KB_POSITIVE_TRUST_VERIFIED'],
        userMessages: ['Target identity authenticated.'],
        evidenceList: [],
      );

      final token = gateway.createToken(
        scanId: 'scan-3',
        actionType: DestinationActionType.viewUrl,
        canonicalTarget: 'https://portal.gov.example',
      );

      final res = await gateway.executeAction(evaluation: evaluation, token: token);
      expect(res.success, isTrue);
      expect(res.status, 'EXECUTED');
      expect(dispatcher.dispatchedIntents.contains('viewUrl:https://portal.gov.example'), isTrue);
    });

    test('rejects duplicate or replayed consent tokens (prevent double-tap and replay)', () async {
      const evaluation = EvaluationResult(
        state: EvaluationState.verified,
        reasonCodes: ['KB_POSITIVE_TRUST_VERIFIED'],
        userMessages: ['Target identity authenticated.'],
        evidenceList: [],
      );

      final token = gateway.createToken(
        scanId: 'scan-4',
        actionType: DestinationActionType.viewUrl,
        canonicalTarget: 'https://portal.gov.example',
      );

      // First execution succeeds
      final res1 = await gateway.executeAction(evaluation: evaluation, token: token);
      expect(res1.success, isTrue);

      // Second duplicate execution is rejected
      final res2 = await gateway.executeAction(evaluation: evaluation, token: token);
      expect(res2.success, isFalse);
      expect(res2.status, 'STALE_TOKEN');
    });

    test('rejects expired consent tokens', () async {
      const evaluation = EvaluationResult(
        state: EvaluationState.verified,
        reasonCodes: ['KB_POSITIVE_TRUST_VERIFIED'],
        userMessages: ['Target identity authenticated.'],
        evidenceList: [],
      );

      final expiredToken = ConsentToken(
        tokenId: 'expired_123',
        scanId: 'scan-5',
        actionType: DestinationActionType.viewUrl,
        canonicalTarget: 'https://portal.gov.example',
        createdAt: DateTime.now().toUtc().subtract(const Duration(minutes: 5)),
        validityDuration: const Duration(seconds: 30),
      );

      final res = await gateway.executeAction(evaluation: evaluation, token: expiredToken);
      expect(res.success, isFalse);
      expect(res.status, 'EXPIRED_TOKEN');
    });
  });

  group('DiagnosticScreen UI and Consent Flow', () {
    testWidgets('renders VERIFIED state and enables execution', (WidgetTester tester) async {
      final qrPayload = QRPayload(entrypoint: 'tile', rawContent: 'https://portal.gov.example');
      const parsedPayload = UrlPayload(rawInput: 'https://portal.gov.example', scheme: 'https', host: 'portal.gov.example');
      const evaluation = EvaluationResult(
        state: EvaluationState.verified,
        reasonCodes: ['KB_POSITIVE_TRUST_VERIFIED'],
        userMessages: ['Target identity authenticated.'],
        evidenceList: [],
      );

      await tester.pumpWidget(
        MaterialApp(
          home: DiagnosticScreen(
            qrPayload: qrPayload,
            parsedPayload: parsedPayload,
            evaluation: evaluation,
            actionGateway: gateway,
          ),
        ),
      );

      expect(find.text('VERDICT: VERIFIED'), findsOneWidget);
      expect(find.text('Target identity authenticated.'), findsOneWidget);

      final proceedBtn = find.byKey(const Key('diagnostic_proceed_button'));
      expect(tester.widget<ElevatedButton>(proceedBtn).onPressed, isNotNull);

      await tester.tap(proceedBtn);
      await tester.pumpAndSettle();

      expect(find.byKey(const Key('execution_result_message')), findsOneWidget);
      expect(dispatcher.dispatchedIntents.length, 1);
    });

    testWidgets('disables action execution button for SUSPICIOUS verdict', (WidgetTester tester) async {
      final qrPayload = QRPayload(entrypoint: 'tile', rawContent: 'http://192.168.1.1');
      const parsedPayload = UrlPayload(rawInput: 'http://192.168.1.1', scheme: 'http', host: '192.168.1.1');
      const evaluation = EvaluationResult(
        state: EvaluationState.suspicious,
        reasonCodes: ['RULE_URL_IP_HOST'],
        userMessages: ['Host is an IP literal.'],
        evidenceList: [],
      );

      await tester.pumpWidget(
        MaterialApp(
          home: DiagnosticScreen(
            qrPayload: qrPayload,
            parsedPayload: parsedPayload,
            evaluation: evaluation,
            actionGateway: gateway,
          ),
        ),
      );

      expect(find.text('VERDICT: SUSPICIOUS'), findsOneWidget);
      expect(find.textContaining('This payload is SUSPICIOUS and has been blocked'), findsOneWidget);

      final proceedBtn = find.byKey(const Key('diagnostic_proceed_button'));
      expect(tester.widget<ElevatedButton>(proceedBtn).onPressed, isNull);
    });

    testWidgets('requires checkbox selection for UNKNOWN verdict before proceed', (WidgetTester tester) async {
      final qrPayload = QRPayload(entrypoint: 'app_icon', rawContent: 'https://unregistered-site.com');
      const parsedPayload = UrlPayload(rawInput: 'https://unregistered-site.com', scheme: 'https', host: 'unregistered-site.com');
      const evaluation = EvaluationResult(
        state: EvaluationState.unknown,
        reasonCodes: ['NO_POSITIVE_PROOF'],
        userMessages: ['Target unproven.'],
        evidenceList: [],
      );

      await tester.pumpWidget(
        MaterialApp(
          home: DiagnosticScreen(
            qrPayload: qrPayload,
            parsedPayload: parsedPayload,
            evaluation: evaluation,
            actionGateway: gateway,
          ),
        ),
      );

      expect(find.text('VERDICT: UNKNOWN'), findsOneWidget);
      expect(find.byKey(const Key('unknown_consent_checkbox')), findsOneWidget);

      // Ensure proceed button is visible in scrollview before tapping
      await tester.ensureVisible(find.byKey(const Key('diagnostic_proceed_button')));
      await tester.pumpAndSettle();

      // Attempt to proceed without ticking checkbox -> shows requirement message
      await tester.tap(find.byKey(const Key('diagnostic_proceed_button')));
      await tester.pumpAndSettle();
      expect(find.textContaining('Action requires explicit two-step confirmation'), findsOneWidget);
      expect(dispatcher.dispatchedIntents, isEmpty);

      // Tick checkbox and proceed -> success
      await tester.ensureVisible(find.byKey(const Key('unknown_consent_checkbox')));
      await tester.pumpAndSettle();
      await tester.tap(find.byKey(const Key('unknown_consent_checkbox')));
      await tester.pumpAndSettle();

      await tester.ensureVisible(find.byKey(const Key('diagnostic_proceed_button')));
      await tester.pumpAndSettle();
      await tester.tap(find.byKey(const Key('diagnostic_proceed_button')));
      await tester.pumpAndSettle();

      expect(dispatcher.dispatchedIntents.length, 1);
    });
  });
}
