import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:peek_in_qr/core/payload/qr_payload.dart';
import 'package:peek_in_qr/features/scanner/scanner_screen.dart';
import 'package:peek_in_qr/main.dart';

void main() {
  group('QRPayload Model Invariants', () {
    test('creates payload with unique UUID and inert contents', () {
      final p1 = QRPayload(
        entrypoint: 'tile',
        rawContent: 'https://example.com',
      );
      final p2 = QRPayload(
        entrypoint: 'tile',
        rawContent: 'https://example.com',
      );

      expect(p1.scanId, isNotEmpty);
      expect(p2.scanId, isNotEmpty);
      expect(p1.scanId, isNot(equals(p2.scanId)));
      expect(p1.entrypoint, 'tile');
      expect(p1.rawContent, 'https://example.com');
      expect(p1.timestamp, isNotNull);
    });

    test('masks preview for long payload safely without throwing', () {
      final longPayload =
          'https://malicious-site.attacker.invalid/login?session=${'A' * 100}';
      final payload = QRPayload(
        entrypoint: 'app_icon',
        rawContent: longPayload,
      );

      expect(payload.maskedPreview.contains('...'), isTrue);
      expect(payload.maskedPreview.length, lessThan(longPayload.length));
    });
  });

  group('ScannerScreen UI and Inert Handling', () {
    testWidgets('renders scanner screen with inert gate notice', (
      WidgetTester tester,
    ) async {
      await tester.pumpWidget(
        const MaterialApp(home: ScannerScreen(initialEntrypoint: 'tile')),
      );

      expect(find.text('Peek-in QR Scanner'), findsOneWidget);
      expect(find.text('Launch Source: TILE'), findsOneWidget);
      expect(find.text('Inert Gate Active'), findsOneWidget);
      expect(
        find.text('Payload will remain inert upon decode'),
        findsOneWidget,
      );
    });

    testWidgets(
      'capturing payload renders inert card and does not auto-execute',
      (WidgetTester tester) async {
        QRPayload? captured;
        await tester.pumpWidget(
          MaterialApp(
            home: ScannerScreen(
              initialEntrypoint: 'tile',
              onPayloadCaptured: (p) => captured = p,
            ),
          ),
        );

        // Enter untrusted URI into the input field
        const testUri = 'https://suspicious-test.example.com/login';
        await tester.enterText(
          find.byKey(const Key('qr_input_field')),
          testUri,
        );
        await tester.tap(find.byKey(const Key('simulate_scan_button')));
        await tester.pumpAndSettle();

        // Check captured payload
        expect(captured, isNotNull);
        expect(captured!.rawContent, testUri);
        expect(captured!.entrypoint, 'tile');

        // Verify the inert payload card is displayed
        expect(find.byKey(const Key('inert_payload_card')), findsOneWidget);
        expect(
          find.text('Captured Inert Payload (No Action Taken)'),
          findsOneWidget,
        );
        expect(find.text(testUri), findsOneWidget);

        // Test discarding the payload (scroll into view first in SingleChildScrollView)
        await tester.ensureVisible(
          find.byKey(const Key('clear_payload_button')),
        );
        await tester.pumpAndSettle();
        await tester.tap(find.byKey(const Key('clear_payload_button')));
        await tester.pumpAndSettle();
        expect(find.byKey(const Key('inert_payload_card')), findsNothing);
      },
    );
  });

  group('PeekInQRApp Shell Launch', () {
    testWidgets('PeekInQRApp launches and initializes ScannerScreen', (
      WidgetTester tester,
    ) async {
      await tester.pumpWidget(const PeekInQRApp());
      await tester.pumpAndSettle();

      expect(find.byType(ScannerScreen), findsOneWidget);
      expect(find.text('Peek-in QR Scanner'), findsOneWidget);
    });
  });
}
