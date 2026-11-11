import 'package:flutter/material.dart';
import '../../core/execution/action_gateway.dart';
import '../../core/fusion/fusion_engine.dart';
import '../../core/kb/kb_models.dart';
import '../../core/kb/kb_repository.dart';
import '../../core/payload/payload_parser.dart';
import '../../core/payload/qr_payload.dart';
import '../diagnostics/diagnostic_screen.dart';

/// Scanner screen that captures QR payloads in an inert state,
/// runs deterministic evaluation, records redacted history, and navigates
/// to diagnostics for ActionGateway consent.
class ScannerScreen extends StatefulWidget {
  final String initialEntrypoint;
  final KnowledgeBaseRepository? kbRepository;
  final ActionGateway? actionGateway;
  final Function(QRPayload)? onPayloadCaptured;

  const ScannerScreen({
    super.key,
    this.initialEntrypoint = 'app_icon',
    this.kbRepository,
    this.actionGateway,
    this.onPayloadCaptured,
  });

  @override
  State<ScannerScreen> createState() => _ScannerScreenState();
}

class _ScannerScreenState extends State<ScannerScreen> {
  final TextEditingController _mockInputController = TextEditingController();
  late final KnowledgeBaseRepository _kbRepo;
  late final ActionGateway _actionGateway;
  late final FusionEngine _fusionEngine;
  QRPayload? _latestPayload;

  @override
  void initState() {
    super.initState();
    _kbRepo = widget.kbRepository ?? KnowledgeBaseRepository();
    _actionGateway = widget.actionGateway ?? ActionGateway();
    _fusionEngine = FusionEngine(kbRepository: _kbRepo);
  }

  void _handlePayload(String rawString) {
    if (rawString.isEmpty) return;

    final payload = QRPayload(
      entrypoint: widget.initialEntrypoint,
      rawContent: rawString,
    );

    setState(() {
      _latestPayload = payload;
    });

    if (widget.onPayloadCaptured != null) {
      widget.onPayloadCaptured!(payload);
    }
  }

  void _navigateToDiagnostics() {
    if (_latestPayload == null) return;

    final parsed = PayloadParser.parse(_latestPayload!.rawContent);
    final evaluation = _fusionEngine.evaluate(parsed);

    // Record redacted scan in repository history
    _kbRepo.recordScan(
      ScanRecord(
        scanId: _latestPayload!.scanId,
        timestamp: _latestPayload!.timestamp,
        payloadType: parsed.type.name.toUpperCase(),
        evaluationState: evaluation.state.name.toUpperCase(),
        reasonCodes: evaluation.reasonCodes,
        consentAction: 'PENDING',
        redactedSummary: _latestPayload!.maskedPreview,
      ),
    );

    Navigator.of(context).push(
      MaterialPageRoute(
        builder: (_) => DiagnosticScreen(
          qrPayload: _latestPayload!,
          parsedPayload: parsed,
          evaluation: evaluation,
          actionGateway: _actionGateway,
        ),
      ),
    );
  }

  @override
  void dispose() {
    _mockInputController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Peek-in QR Scanner'),
        backgroundColor: Colors.indigo,
        foregroundColor: Colors.white,
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            // Status and Entry Point badge
            Card(
              elevation: 2,
              child: Padding(
                padding: const EdgeInsets.all(12.0),
                child: Row(
                  children: [
                    const Icon(Icons.security, color: Colors.indigo),
                    const SizedBox(width: 8),
                    Expanded(
                      child: Text(
                        'Launch Source: ${widget.initialEntrypoint.toUpperCase()}',
                        style: const TextStyle(fontWeight: FontWeight.bold),
                      ),
                    ),
                    const Chip(
                      label: Text('Inert Gate Active'),
                      backgroundColor: Colors.amberAccent,
                    ),
                  ],
                ),
              ),
            ),
            const SizedBox(height: 16),

            // Camera preview viewfinder placeholder / Scanner View
            Container(
              height: 240,
              decoration: BoxDecoration(
                color: Colors.black87,
                borderRadius: BorderRadius.circular(12),
                border: Border.all(color: Colors.indigoAccent, width: 2),
              ),
              child: Center(
                child: Column(
                  mainAxisAlignment: MainAxisAlignment.center,
                  children: const [
                    Icon(
                      Icons.qr_code_scanner,
                      size: 64,
                      color: Colors.white70,
                    ),
                    SizedBox(height: 8),
                    Text(
                      'Point camera at QR code',
                      style: TextStyle(color: Colors.white70, fontSize: 16),
                    ),
                    SizedBox(height: 4),
                    Text(
                      'Payload will remain inert upon decode',
                      style: TextStyle(color: Colors.amberAccent, fontSize: 12),
                    ),
                  ],
                ),
              ),
            ),
            const SizedBox(height: 20),

            // Synthetic / Manual QR Payload Entry (for testing & verification)
            Card(
              elevation: 1,
              child: Padding(
                padding: const EdgeInsets.all(12.0),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [
                    const Text(
                      'Decode / Test Ingestion:',
                      style: TextStyle(fontWeight: FontWeight.bold),
                    ),
                    const SizedBox(height: 8),
                    TextField(
                      key: const Key('qr_input_field'),
                      controller: _mockInputController,
                      decoration: const InputDecoration(
                        hintText: 'Enter URL, UPI, tel, Wi-Fi or text payload',
                        border: OutlineInputBorder(),
                        isDense: true,
                      ),
                    ),
                    const SizedBox(height: 8),
                    ElevatedButton.icon(
                      key: const Key('simulate_scan_button'),
                      onPressed: () {
                        _handlePayload(_mockInputController.text);
                        _mockInputController.clear();
                      },
                      icon: const Icon(Icons.qr_code),
                      label: const Text('Capture Inert QR Payload'),
                      style: ElevatedButton.styleFrom(
                        backgroundColor: Colors.indigo,
                        foregroundColor: Colors.white,
                      ),
                    ),
                  ],
                ),
              ),
            ),
            const SizedBox(height: 20),

            // Captured Inert Payload Display
            if (_latestPayload != null) ...[
              Card(
                key: const Key('inert_payload_card'),
                color: Colors.grey.shade100,
                elevation: 3,
                child: Padding(
                  padding: const EdgeInsets.all(16.0),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Row(
                        children: const [
                          Icon(Icons.lock_outline, color: Colors.indigo),
                          SizedBox(width: 8),
                          Text(
                            'Captured Inert Payload (No Action Taken)',
                            style: TextStyle(
                              fontWeight: FontWeight.bold,
                              fontSize: 16,
                            ),
                          ),
                        ],
                      ),
                      const Divider(),
                      Text('Scan ID: ${_latestPayload!.scanId}'),
                      Text(
                        'Timestamp: ${_latestPayload!.timestamp.toIso8601String()}',
                      ),
                      Text('Origin: ${_latestPayload!.entrypoint}'),
                      const SizedBox(height: 8),
                      const Text(
                        'Raw Content (Ephemerally Held):',
                        style: TextStyle(fontWeight: FontWeight.w600),
                      ),
                      Container(
                        padding: const EdgeInsets.all(8),
                        margin: const EdgeInsets.only(top: 4),
                        decoration: BoxDecoration(
                          color: Colors.white,
                          borderRadius: BorderRadius.circular(4),
                          border: Border.all(color: Colors.grey.shade300),
                        ),
                        child: SelectableText(
                          _latestPayload!.maskedPreview,
                          key: const Key('payload_preview_text'),
                          style: const TextStyle(fontFamily: 'monospace'),
                        ),
                      ),
                      const SizedBox(height: 12),
                      Row(
                        children: [
                          ElevatedButton.icon(
                            key: const Key('inspect_diagnostics_button'),
                            onPressed: _navigateToDiagnostics,
                            icon: const Icon(Icons.analytics_outlined),
                            label: const Text('Inspect Diagnostics'),
                            style: ElevatedButton.styleFrom(
                              backgroundColor: Colors.indigo,
                              foregroundColor: Colors.white,
                            ),
                          ),
                          const SizedBox(width: 8),
                          OutlinedButton.icon(
                            key: const Key('clear_payload_button'),
                            onPressed: () {
                              setState(() {
                                _latestPayload = null;
                              });
                            },
                            icon: const Icon(Icons.delete_outline),
                            label: const Text('Discard'),
                          ),
                        ],
                      ),
                    ],
                  ),
                ),
              ),
            ],
          ],
        ),
      ),
    );
  }
}
