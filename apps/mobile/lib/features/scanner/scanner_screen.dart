import 'package:flutter/material.dart';
import '../../core/payload/qr_payload.dart';

/// Scanner screen that captures QR payloads in an inert state.
///
/// Invariant:
/// Upon scanning or inputting a QR payload, it is displayed in the inert
/// capture view. No external URL open, payment application launch, or
/// phone dialing is triggered.
class ScannerScreen extends StatefulWidget {
  final String initialEntrypoint;
  final Function(QRPayload)? onPayloadCaptured;

  const ScannerScreen({
    super.key,
    this.initialEntrypoint = 'app_icon',
    this.onPayloadCaptured,
  });

  @override
  State<ScannerScreen> createState() => _ScannerScreenState();
}

class _ScannerScreenState extends State<ScannerScreen> {
  final TextEditingController _mockInputController = TextEditingController();
  QRPayload? _latestPayload;

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
                    Icon(Icons.qr_code_scanner, size: 64, color: Colors.white70),
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
                            style: TextStyle(fontWeight: FontWeight.bold, fontSize: 16),
                          ),
                        ],
                      ),
                      const Divider(),
                      Text('Scan ID: ${_latestPayload!.scanId}'),
                      Text('Timestamp: ${_latestPayload!.timestamp.toIso8601String()}'),
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
